"""Minimal pytest-compatible test runner for offline environments.

This shim provides just enough functionality for the Edge Sentinel test
suite to execute without the external pytest dependency. It supports the
subset of the pytest API used by the project: fixtures (including
``autouse``), the ``monkeypatch`` helper, ``mark.parametrize``, and a
basic command-line runner invoked via ``python -m pytest``.
"""

from __future__ import annotations

import inspect
import importlib
import importlib.util
import os
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

__all__ = ["fixture", "mark", "main", "MonkeyPatch", "raises"]


@dataclass
class _FixtureDef:
    func: Callable[..., Any]
    autouse: bool = False


_FIXTURES: Dict[str, _FixtureDef] = {}
_IMPORTED_CONFTEST: set[Path] = set()


def _register_fixture(name: str, func: Callable[..., Any], autouse: bool = False) -> None:
    _FIXTURES[name] = _FixtureDef(func=func, autouse=autouse)


def fixture(func: Optional[Callable[..., Any]] = None, *, autouse: bool = False) -> Callable[..., Any]:
    """Decorate a function to register it as a fixture."""

    def register(target: Callable[..., Any]) -> Callable[..., Any]:
        _register_fixture(target.__name__, target, autouse=autouse)
        return target

    if func is None:
        return register
    return register(func)


class MonkeyPatch:
    """Very small subset of pytest's MonkeyPatch helper."""

    _UNSET = object()

    def __init__(self) -> None:
        self._actions: List[Tuple[str, Any, Any]] = []

    def setenv(self, name: str, value: str) -> None:
        previous = os.environ.get(name, MonkeyPatch._UNSET)
        os.environ[name] = value
        self._actions.append(("env", name, previous))

    def delenv(self, name: str, raising: bool = True) -> None:
        previous = os.environ.get(name, MonkeyPatch._UNSET)
        if previous is MonkeyPatch._UNSET:
            if raising:
                raise KeyError(name)
        else:
            os.environ.pop(name, None)
        self._actions.append(("env", name, previous))

    def setattr(self, obj: Any, name: str, value: Any) -> None:
        target = obj
        previous = getattr(target, name, MonkeyPatch._UNSET)
        setattr(target, name, value)
        self._actions.append(("attr", (target, name), previous))

    def undo(self) -> None:
        while self._actions:
            kind, target, previous = self._actions.pop()
            if kind == "env":
                if previous is MonkeyPatch._UNSET:
                    os.environ.pop(target, None)
                else:
                    os.environ[target] = previous
            elif kind == "attr":
                obj, name = target
                if previous is MonkeyPatch._UNSET:
                    delattr(obj, name)
                else:
                    setattr(obj, name, previous)


def raises(expected: type[BaseException]) -> Any:
    """Minimal context manager asserting a block raises the expected exception."""

    class _RaisesContext:
        def __enter__(self) -> None:  # pragma: no cover - trivial
            return None

        def __exit__(self, exc_type, exc, tb) -> bool:
            if exc_type is None:
                raise AssertionError(f"Did not raise {expected!r}")
            return issubclass(exc_type, expected)

    return _RaisesContext()


def _monkeypatch_fixture() -> Iterator[MonkeyPatch]:
    mp = MonkeyPatch()
    try:
        yield mp
    finally:
        mp.undo()


_register_fixture("monkeypatch", _monkeypatch_fixture)


class _MarkHelper:
    def parametrize(self, argnames: str, argvalues: Sequence[Any]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        names = [name.strip() for name in argnames.split(",") if name.strip()]

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            cases: List[Tuple[Any, ...]] = []
            for value in argvalues:
                if isinstance(value, tuple):
                    cases.append(value)
                else:
                    cases.append((value,))
            setattr(func, "_pytest_parametrize", (names, cases))
            return func

        return decorator


mark = _MarkHelper()


class _FixtureContext:
    def __init__(self) -> None:
        self._values: Dict[str, Any] = {}
        self._finalizers: List[Callable[[], None]] = []
        self._active: set[str] = set()

    def get(self, name: str) -> Any:
        if name in self._values:
            return self._values[name]
        if name in self._active:
            raise RuntimeError(f"Circular fixture dependency detected for '{name}'")
        fixture_def = _FIXTURES.get(name)
        if fixture_def is None:
            raise RuntimeError(f"Unknown fixture '{name}'")
        self._active.add(name)
        try:
            value = self._invoke(fixture_def.func)
        finally:
            self._active.remove(name)
        self._values[name] = value
        return value

    def _invoke(self, func: Callable[..., Any]) -> Any:
        parameters = inspect.signature(func).parameters
        kwargs = {param: self.get(param) for param in parameters}
        result = func(**kwargs)
        if inspect.isgenerator(result):
            generator = result
            try:
                value = next(generator)
            except StopIteration:
                value = None

            def finalizer(gen: Iterator[Any] = generator) -> None:
                try:
                    next(gen)
                except StopIteration:
                    pass

            self._finalizers.append(finalizer)
            return value
        return result

    def setup_autouse(self) -> None:
        for name, fixture_def in list(_FIXTURES.items()):
            if fixture_def.autouse:
                self.get(name)

    def finalize(self) -> None:
        while self._finalizers:
            finalizer = self._finalizers.pop()
            try:
                finalizer()
            except Exception:
                # Suppress errors during cleanup to avoid masking test failures.
                pass


class _TestRunner:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.total = 0
        self.passed = 0
        self.failed: List[Tuple[str, str]] = []

    def run(self, targets: Sequence[str]) -> bool:
        if not targets:
            targets = ["tests"]
        for target in targets:
            self._run_target(target)
        if self.failed:
            for name, tb in self.failed:
                print(f"FAILED: {name}")
                print(tb)
            print(f"{self.passed} passed, {len(self.failed)} failed")
            return False
        if not self.quiet:
            print(f"{self.passed} passed")
        return True

    def _run_target(self, target: str) -> None:
        path = Path(target)
        if path.is_dir():
            self._load_conftest(path)
            for child in sorted(path.iterdir()):
                if child.name == "__pycache__":
                    continue
                if child.is_dir():
                    self._run_target(str(child))
                elif child.suffix == ".py" and child.name.startswith("test_"):
                    self._run_module_from_path(child)
        elif path.is_file():
            if path.name == "conftest.py":
                self._import_module_from_path(path)
            else:
                self._run_module_from_path(path)
        else:
            module = importlib.import_module(target)
            self._run_module(module, target)

    def _load_conftest(self, directory: Path) -> None:
        candidate = directory / "conftest.py"
        if candidate.exists() and candidate not in _IMPORTED_CONFTEST:
            self._import_module_from_path(candidate)
            _IMPORTED_CONFTEST.add(candidate)

    def _import_module_from_path(self, path: Path) -> ModuleType:
        module_name = f"_pytest_{path.stem}_{len(sys.modules)}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot import module from {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    def _run_module_from_path(self, path: Path) -> None:
        module = self._import_module_from_path(path)
        self._run_module(module, str(path))

    def _run_module(self, module: ModuleType, location: str) -> None:
        for name, obj in vars(module).items():
            if name.startswith("test_") and callable(obj):
                self._run_callable(obj, f"{location}::{name}")
            elif inspect.isclass(obj) and name.startswith("Test"):
                for attr_name, attr in vars(obj).items():
                    if attr_name.startswith("test_") and callable(attr):
                        self._run_callable(attr, f"{location}::{obj.__name__}::{attr_name}", cls=obj)

    def _run_callable(self, func: Callable[..., Any], display_name: str, cls: Optional[type] = None) -> None:
        param_info = getattr(func, "_pytest_parametrize", None)
        if param_info is None:
            self._execute_test(func, display_name, cls, case_kwargs={})
        else:
            names, cases = param_info
            for index, case in enumerate(cases):
                kwargs = {names[i]: case[i] for i in range(len(names))}
                label = f"{display_name}[{index}]"
                self._execute_test(func, label, cls, case_kwargs=kwargs)

    def _execute_test(
        self,
        func: Callable[..., Any],
        display_name: str,
        cls: Optional[type] = None,
        *,
        case_kwargs: Mapping[str, Any],
    ) -> None:
        self.total += 1
        context = _FixtureContext()
        instance = cls() if cls is not None else None
        try:
            context.setup_autouse()
            call_kwargs = self._build_call_kwargs(func, instance, case_kwargs, context)
            if instance is not None:
                func(instance, **call_kwargs)
            else:
                func(**call_kwargs)
        except Exception as exc:  # pragma: no cover - exercised via failure paths
            tb = traceback.format_exc()
            self.failed.append((display_name, tb))
        else:
            self.passed += 1
        finally:
            context.finalize()

    def _build_call_kwargs(
        self,
        func: Callable[..., Any],
        instance: Optional[Any],
        case_kwargs: Mapping[str, Any],
        context: _FixtureContext,
    ) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {}
        for name, parameter in inspect.signature(func).parameters.items():
            if name == "self" and instance is not None:
                continue
            if name in case_kwargs:
                kwargs[name] = case_kwargs[name]
            else:
                kwargs[name] = context.get(name)
        return kwargs


def main(args: Optional[Sequence[str]] = None) -> int:
    args = list(args) if args is not None else sys.argv[1:]
    quiet = False
    targets: List[str] = []
    for arg in args:
        if arg in {"-q", "--quiet"}:
            quiet = True
        else:
            targets.append(arg)
    runner = _TestRunner(quiet=quiet)
    success = runner.run(targets)
    return 0 if success else 1

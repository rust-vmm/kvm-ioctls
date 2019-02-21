# kvm-ioctls

TODO

## Running the tests

### Dependencies
**[NOTE]** This is a temporary state of affairs; Most likely we will manage
the dependencies using a container.
- python >= 3.5
- pytest
- kcov
- cargo kcov
- cargo fmt
- cargo clippy
- target x86_64-unknown-linux-musl

```
$ pytest tests/ -vv
============================= test session starts ==============================
platform linux -- Python 3.6.8, pytest-3.8.0, py-1.6.0, pluggy-0.7.1 -- /usr/bin/python3.6
cachedir: .pytest_cache
rootdir: /home/local/ANT/fandree/sources/work/rust-vmm/kvm-ioctls, inifile:
collected 6 items
tests/test_build.py::test_build PASSED                                   [ 16%]
tests/test_build.py::test_build_musl PASSED                              [ 33%]
tests/test_correctness.py::test_style PASSED                             [ 50%]
tests/test_correctness.py::test_clippy PASSED                            [ 66%]
tests/test_correctness.py::test_unittests PASSED                         [ 83%]
tests/test_coverage.py::test_coverage PASSED                             [100%]

=========================== 6 passed in 7.08 seconds ===========================
```

### Adaptive Coverage

The line coverage is saved in [tests/coverage](tests/coverage). To update the
coverage before submitting a PR, run the coverage test:
```bash
pytest tests/test_coverage.py
```

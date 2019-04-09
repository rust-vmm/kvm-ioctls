# kvm-ioctls

TODO

## Running the tests

TODO

### Adaptive Coverage

The line coverage is saved in [tests/coverage](tests/coverage). To update the
coverage before submitting a PR, run the coverage test:

```bash
docker run --device=/dev/kvm \
           -it \
           --security-opt seccomp=unconfined \
           --volume $(pwd)/kvm-ioctls:/kvm-ioctls \
           fandree/rust-vmm-dev
cd kvm-ioctls/
pytest tests/test_coverage.py
```

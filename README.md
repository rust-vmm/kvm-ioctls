# kvm-ioctls

TODO

## Running the tests

TODO

### Test Profiles

The integration tests support two test profiles:
- **devel**: this is the recommended profile for running the integration tests
  on a local development machine.
- **ci** (default option): this is the profile used when running the
  integration tests as part of the the Continuous Integration (CI).

The test profiles are applicable to tests that run using pytest. Currently only
the [coverage test](tests/test_coverage.py) follows this model as all the other
integration tests are run using the
[Buildkite pipeline](https://buildkite.com/rust-vmm/kvm-ioctls-ci).

The difference between is declaring tests as passed or failed:
- with the **devel** profile the coverage test passes if the current coverage
  is equal or higher than the upstream coverage value. In case the current
  coverage is higher, the coverage file is updated to the new coverage value.
- with the **ci** profile the coverage test passes only if the current coverage
  is equal to the upstream coverage value.

Further details about the coverage test can be found in the
[Adaptive Coverage](#adaptive-coverage) section.

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
pytest --profile=devel tests/test_coverage.py
```

If the PR coverage is higher than the upstream coverage, the coverage file
needs to be manually added to the commit before submitting the PR:

```bash
git add tests/coverage
```

Failing to do so will generate a fail on the CI pipeline when publishing the
PR.

**NOTE:** The coverage file is only updated in the `devel` test profile. In
the `ci` profile the coverage test will fail if the current coverage is higher
than the coverage reported in [tests/coverage](tests/coverage).

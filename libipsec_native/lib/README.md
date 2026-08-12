# Library output directory

Running `make` in the parent `libipsec_native` directory creates:

```text
lib/libipsec_native.a
lib/libipsec_native.so
```

Running `make -f Makefile.host` creates the static archive at the same
`lib/libipsec_native.a` path. Generated library files are ignored by Git.

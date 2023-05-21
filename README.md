# cedargo

Go bindings for the Cedar policy evaluation engine.

## Building

```
cd cedar-go-bindings
cargo build --release
cd ..

cp cedar-go-bindings/target/release/*.dylib ./lib

go build -ldflags="-r ./lib"
```

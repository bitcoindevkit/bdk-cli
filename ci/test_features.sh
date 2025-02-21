#!/bin/bash

feature_combinations=(
    "default"
    "repl"
    "sqlite"
    "electrum"
    "esplora"
    "verify"
    "compiler"
    "repl sqlite"
    "repl electrum"
    "repl esplora"
    "repl verify"
    "repl compiler"
    "sqlite electrum"
    "sqlite esplora"
    "sqlite verify"
    "sqlite compiler"
    "verify esplora compiler"
    "verify esplora repl"
    "verify compiler repl"
    "verify esplora compiler repl"
)

for features in "${feature_combinations[@]}"; do
    echo "Testing with features: $features"
    
    if ! cargo build --features "$features"; then
        echo "Build failed with features: $features"
        exit 1
    fi
    
    if ! cargo test --features "$features"; then
        echo "Tests failed with features: $features"
        exit 1
    fi
    
    echo "Tests passed with features: $features"
    echo "----------------------------------------"
done

echo "All feature combinations tested successfully!"

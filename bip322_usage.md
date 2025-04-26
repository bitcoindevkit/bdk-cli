# Testing the Bip322 Subcommand

Ensure you are in a secure environment to prevent key exposure.

To build, run `cargo build --features bip322`
For testing purposes only, use `L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k` for private key.

## Signing and Verifying with Different Address Types
1. **Signing and Verifying with Simple**
- Sign a Message(Non-Interactive with `--key_file`):
    ```bash
    ./target/debug/bdk-cli bip322 sign \
    --key_file /path/to/private_key.txt \
    --message "Hello World" \
    --address bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l \
    --signature_type simple
    ```

    - The file `/path/to/private_key.txt` should contain the WIF private key (e.g., `L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k`).


- Sign a Message(Interactive):
    ```bash
    ./target/debug/bdk-cli bip322 sign \
    --message "Hello World" \
    --address bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l \
    --signature_type simple
    ```

    - When running this command, the tool will prompt:
        ```bash
        Enter WIF private key:
        ```
    - Enter the WIF private key (e.g., `L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k`). The input will not be displayed on the console for security.

- Expected Output:
    ```json
    {
    "signature": "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
    }
    ```
- Verify the Signature:
    ```bash
    ./target/debug/bdk-cli bip322 verify \
    --signature "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy" \
    --message "Hello World" \
    --address bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l \
    --signature_type simple
    ```

    - No private key is required for verifying the `simple` signature type.

- Expected Output:
    ```json
    {
    "is_valid": true
    }
    ```

2. **Signing and Verifying with Legacy**
- Sign a Message(Non-Interactive with `--key_file`):
    ```bash
    ./target/debug/bdk-cli bip322 sign \
    --key_file /path/to/private_key.txt \
    --message "Hello World" \
    --address 14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc \
    --signature_type legacy
    ```
    - The file `/path/to/private_key.txt` should contain the WIF private key (e.g., `L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k`).

- Sign a Message (Interactive):
    ```bash
    ./target/debug/bdk-cli bip322 sign \
    --message "Hello World" \
    --address 14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc \
    --signature_type legacy
    ```

    - When running this command, the tool will prompt:
        ```bash
        Enter WIF private key:
        ```
    - Enter the WIF private key (e.g., `L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k`). The input will not be displayed on the console for security.


- Expected Output:
    ```json
    {
    "signature": "MEUCIQDltsYvnmyS3gba+u+JeEB++nag6FYy1fNEfRBShUF+awIgBrlCXPIZaYs8Yuayg0ZqjyiCbLy9pzZIS7JWT65/nsUB"
    }
    ```
- Verify the Signature (Non-Interactive with `--key_file`):
    ```bash
    ./target/debug/bdk-cli bip322 verify \
    --signature "MEUCIQDltsYvnmyS3gba+u+JeEB++nag6FYy1fNEfRBShUF+awIgBrlCXPIZaYs8Yuayg0ZqjyiCbLy9pzZIS7JWT65/nsUB" \
    --message "Hello World" \
    --address 14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc \
    --signature_type legacy \
    --key_file /path/to/private_key.txt
    ```

    - The file /path/to/private_key.txt must contain the WIF private key used for signing.

- Verify the Signature (Interactive):
    ```bash
    ./target/debug/bdk-cli bip322 verify \
    --signature "MEUCIQDltsYvnmyS3gba+u+JeEB++nag6FYy1fNEfRBShUF+awIgBrlCXPIZaYs8Yuayg0ZqjyiCbLy9pzZIS7JWT65/nsUB" \
    --message "Hello World" \
    --address 14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc \
    --signature_type legacy
    ```
    - When running this command, the tool will prompt:
    ```bash
    Enter WIF private key:
    ```
    - Enter the WIF private key used for signing.

- Expected Output:
    ```json
    {
    "is_valid": true
    }
    ```

3. Signing and Verifying with Full
- Sign a Message (Non-Interactive with `--key_file`):
    Same way with Simple, only change the signature type to full

- Sign a Message (Interactive):
    Same way with Simple, only change the signature type to full

- Verify the Signature:
Use the signature from the above command in a similar verify command.

## Notes for Testing
- **Security**: Always handle private keys securely. Use the `--key_file` option or the interactive prompt to avoid exposing keys in command-line arguments or insecure environments. For production use, consider using the `wallet` subcommand for secure key generation.

- **Error Handling:** If the signature type, address, or private key is invalid, the CLI will return an error message. Test with invalid inputs (e.g., an empty `--key_file` or invalid WIF key) to ensure proper error handling.

- **Interactive Mode:** When not providing `--key_file`, the tool will prompt for the private key. The input is not echoed to the console for security. If an empty input is provided, an error will be returned.

- **Legacy Verification:** For the `legacy` signature type, a private key is required during verification. Ensure the same key used for signing is provided via `--key_file` or interactively.


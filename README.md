# Example Python Offline Validation Caching

This is an example of caching validation responses locally for offline use. This particular Python script caches successful validation responses, along with the response's cryptographic signature, to the filesystem for 1 day, making sure a license can be validated in an offline environment for 1 day. Storing the cryptographic response signature prevents the cached data from being tampered with.

Feel free to cache to another form of local storage, e.g. registry, etc.

## Running the example

First up, add an environment variable containing your public key:

```bash
# Your Keygen account's Ed25519 verify key
export KEYGEN_VERIFY_KEY="YOUR_KEYGEN_ED25519_VERIFY_KEY"

# Your Keygen account ID
export KEYGEN_ACCOUNT_ID="YOUR_KEYGEN_ACCOUNT_ID"
```

You can either run each line above within your terminal session before starting the app, or you can add the above contents to your `~/.bashrc` file and then run `source ~/.bashrc` after saving the file.

Next, install dependencies with [`pip`](https://packaging.python.org/):

```
pip install -r requirements.txt
```

Then run the script, passing in a license key to validate:

```
python main.py some-license-key-here
```

Once you've ran the script at least once while connected to the internet i.e. online, you may run the script while disconnected from the internet, which will utilize the offline cache.

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!

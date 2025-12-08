# react-native-libsignal-client

A React Native wrapper around the official `libsignal` client library (Rust core exposed via Swift/Java/Kotlin bindings) enabling end‑to‑end encryption (Signal Protocol) in React Native apps.

## Features

- Signal protocol primitives (identity keys, sessions, prekeys, message encryption/decryption)
- zkgroup / group-related APIs surfaced from upstream
- TypeScript typings
- Expo config plugin (adds iOS pod + required build settings automatically)
- Example app with runnable protocol tests

---

## Installation

```bash
npm install react-native-libsignal-client
# or
yarn add react-native-libsignal-client
```

### Expo (Recommended)

Add the plugin to `app.json` / `app.config.(js|ts)`:

```json
{
  "expo": {
    "plugins": ["react-native-libsignal-client"]
  }
}
```

Then generate native projects and run:

```bash
npx expo prebuild
npx expo run:ios   # or: npx expo run:android
```

The plugin:

- Injects the `LibSignalClient` CocoaPod (tag pinned)
- Sets `use_frameworks! :linkage => :dynamic` (via `expo-build-properties`)
- Adds the required Rust FFI checksum environment line

### React Native CLI (Bare) – iOS

1. Install Rust & targets (first time only):

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
   ```

2. Edit your `ios/Podfile` (if you are NOT using the Expo config plugin):

   ```ruby
   platform :ios, '12.0'
   use_frameworks! :linkage => :dynamic

   ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] ||= 'e12f6f64eb0ed503c363f3b3830c4c62976cceec04122cd6deee66f5106c482d'

   target 'YourApp' do
     # ... other pods
     pod 'LibSignalClient', :git => 'https://github.com/signalapp/libsignal.git', :tag => 'v0.70.0'
   end
   ```

3. Install pods:

   ```bash
   cd ios && pod install
   ```

4. Open the workspace or run:

   ```bash
   npx react-native run-ios
   ```

### React Native CLI – Android

No extra Gradle configuration is required. (The library ships pure JS + native upstream dependency only on iOS via CocoaPods.)  
If you hit Java compilation toolchain issues, ensure:

- Gradle JVM / toolchain uses Java 17+
- Android Gradle Plugin version aligns with your RN version

---

## Example Project & Tests

An `example/` app is included (Expo prebuild output) that doubles as an integration test harness.

Run it:

```bash
cd example
yarn install
npx expo prebuild   # (only if you cleaned native)
npx expo run:ios    # or: npx expo run:android
```

During app startup it executes protocol tests found in `example/tests/` (crypto/session/zkgroup scenarios).  
You can modify or add tests there to validate your own flows.

Headless test tips:

- Add lightweight wrappers in `example/tests/*.ts`
- Use a physical device for performance‑sensitive benchmarking

---

## Upgrading libsignal Version

The plugin currently pins:

```
tag: v0.70.0
checksum: e12f6f64eb0ed503c363f3b3830c4c62976cceec04122cd6deee66f5106c482d
```

To override (Expo users):

```json
{
  "expo": {
    "plugins": [
      ["react-native-libsignal-client", { "tag": "v0.71.0", "checksum": "<new_checksum>" }]
    ]
  }
}
```

(Option support to be documented once exposed—until then, fork or patch the plugin.)

Bare users: change the `:tag` and checksum line in your Podfile and run `pod update LibSignalClient`.

Obtain the new checksum from the upstream libsignal GitHub Release notes.

---

## Usage (Basic Flow)

```typescript
import {
  PrivateKey,
  ProtocolAddress,
  SessionBuilder,
  SessionCipher,
  PreKeyBundle,
} from 'react-native-libsignal-client';

// Identity + registration
const identityKey = PrivateKey.generate();
const registrationId = 42; // store persistently

// Suppose you received a remote prekey bundle (preKeyBundleJson)
const bundle: PreKeyBundle = PreKeyBundle.deserialize(preKeyBundleJson);

const address = new ProtocolAddress('alice', 1);
const store = /* implement & provide a SignalProtocolStore-like object */;

const builder = new SessionBuilder(store, address);
await builder.processPreKeyBundle(bundle);

// Encrypt
const cipher = new SessionCipher(store, address);
const { type, body } = await cipher.encrypt(Buffer.from('Hello, Signal!'));

// Decrypt
const plaintext = await cipher.decrypt(type, body);
console.log(plaintext.toString());
```

Persistence: You must implement storage interfaces (identity, sessions, prekeys, signed prekeys, one-time prekeys). Keep them consistent across launches; losing them will break decryption.

---

## iOS Framework / Static Pod Workarounds

Because `use_frameworks! :linkage => :dynamic` is required for the Swift-based `LibSignalClient` pod, some React Native pods (notably `RNReanimated`, sometimes `RNScreens`) can fail to link with errors like:

```
Undefined symbols for architecture arm64
_OBJC_CLASS_$_RCTEventDispatcher
```

This is a known CocoaPods + mixed linkage quirk. The plugin automatically forces a minimal set of pods to build as static libraries to avoid these issues.

Default static overrides:

- RNReanimated
- RNScreens

You can customize:

```json
{
  "expo": {
    "plugins": [
      [
        "react-native-libsignal-client",
        {
          "ios": {
            "staticPods": ["RNCMaskedView", "ExpoDocumentPicker"],   // add more
            "disableStaticWorkarounds": false
          }
        }
      ]
    ]
  }
}
```

Set `disableStaticWorkarounds: true` to remove the pre_install block and manage linkage manually.

### Overriding libsignal Version / Checksum

The plugin pins a known-good upstream tag & checksum. To test a new upstream release:

```json
{
  "expo": {
    "plugins": [
      [
        "react-native-libsignal-client",
        {
          "ios": {
            "libsignalTag": "v0.71.0",
            "libsignalChecksum": "<release_checksum>"
          }
        }
      ]
    ]
  }
}
```

(Checksum comes from the upstream release notes. A mismatch will cause the pod build script to fail early.)

### How It Works (iOS)

1. `use_frameworks! :linkage => :dynamic` enables building Swift/C modules as frameworks.
2. `LibSignalClient` pod build script downloads / builds the Rust FFI for required architectures.
3. Static override block redefines `build_type` for selected pods so they link into the app binary, preventing missing React symbol linkage.
4. If you remove `use_frameworks!`, the pod will fail (Swift + Rust wrapper expects frameworks).

### When to Add More Static Pods

Add a pod name to `staticPods` if:

- You see "Undefined symbols ..." referencing React classes from that pod.
- You get duplicate symbol errors after adding another dynamic framework—forcing one side static can help.

If everything builds, do not add more; keep surface minimal.

---

## License

This project is licensed under the GNU Affero General Public License v3.0 – see the [LICENSE](LICENSE) file.

It incorporates and depends on upstream [libsignal](https://github.com/signalapp/libsignal) (AGPL-3.0).

Using this library in your application subjects the combined work to AGPLv3 obligations (including network use). If you require a different licensing model, consult Signal’s upstream licensing/commercial options.

---

## Source Availability Notice

In compliance with AGPLv3, the complete corresponding source for this package is available at:
<https://github.com/your-org-or-user/react-native-libsignal-client>

---

## Disclaimer

This binding is not an official Signal distribution. Review upstream changes and audit cryptographic handling for production deployments.

---

## Contributing

Issues and PRs are welcome. Please:

1. Keep changes minimal & auditable
2. Avoid reformat-only PRs
3. Do not bundle unrelated dependency bumps with feature changes

---

## Publishing

For maintainers: see [PUBLISHING.md](PUBLISHING.md) for details on the release process.

---

## Roadmap (Planned)

- Optional plugin params for `tag` / `checksum`
- Documentation for implementing stores

---

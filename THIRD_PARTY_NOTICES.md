# Third-party build tools

## Lightning CSS 1.30.2 — MPL-2.0

Lightning CSS is an unmodified build dependency of Vite and `@tailwindcss/node`.
Its optional native packages are alternative platform builds of the same tool:

- `lightningcss-android-arm64`
- `lightningcss-darwin-arm64`, `lightningcss-darwin-x64`
- `lightningcss-freebsd-x64`
- `lightningcss-linux-arm-gnueabihf`
- `lightningcss-linux-arm64-gnu`, `lightningcss-linux-arm64-musl`
- `lightningcss-linux-x64-gnu`, `lightningcss-linux-x64-musl`
- `lightningcss-win32-arm64-msvc`, `lightningcss-win32-x64-msvc`

All twelve package entries in the supplied SBOM carry MPL-2.0; they are license
review entries, not dependency vulnerability advisories. Versions and integrity
hashes are pinned in `package-lock.json`. The project does not modify their source.

Source: [parcel-bundler/lightningcss](https://github.com/parcel-bundler/lightningcss).
The exact upstream release is 1.30.2. The license is reproduced unmodified in
[licenses/MPL-2.0.txt](licenses/MPL-2.0.txt) from the installed package.

The application source does not import Lightning CSS. Vite and Tailwind use it
during development/build; its native binaries are not application browser assets.
`node_modules/` is excluded from this Git repository. When distributing development
tools, containers, or archives that include these dependencies, retain their
license notices and give recipients access to the corresponding MPL-covered source.
Review the actual contents of each distribution, including its other dependencies.

Mozilla explains that MPL is file-level copyleft, and providing server functionality
over a network alone does not constitute distribution of that server code. Browser
code sent to users does constitute distribution. See the
[MPL FAQ, questions 5, 8, 11 and 17](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).
This notice does not relicense the dependencies or assert that MPL is permissive.

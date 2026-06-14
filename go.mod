module github.com/theQRL/go-qrllib

go 1.25.0

// v0.2.0's release was bound to a stale tag (50d2038) pointing ~80 commits
// behind its own release notes, so `@v0.2.0` serves code that does not match
// what the release describes. The tag is immutable in the module proxy/sumdb
// and must not be moved; this directive makes `go get` warn and excludes the
// version from automatic selection. See RELEASE.md "Manual Releases".
retract v0.2.0

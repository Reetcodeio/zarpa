package fs

import "testing"

func TestGitignorePatterns(t *testing.T) {
	st := ignoreStack{parseIgnore("", `
# comment
*.log
/build
dist/
node_modules
docs/**/*.tmp
!keep.log
**/secret-*
.env*
!.env.example
`)}
	cases := []struct {
		path string
		dir  bool
		want bool
	}{
		{"app.log", false, true},
		{"sub/app.log", false, true},
		{"keep.log", false, false},
		{"build", true, true},
		{"sub/build", true, false}, // anchored to root
		{"dist", true, true},
		{"dist", false, false}, // dir-only pattern
		{"a/b/node_modules", true, true},
		{"docs/x/y/z.tmp", false, true},
		{"docs/z.tmp", false, true},
		{"other/z.tmp", false, false},
		{"deep/dir/secret-1.txt", false, true},
		{".env", false, true},
		{".env.local", false, true},
		{".env.example", false, false},
		{"src/main.go", false, false},
	}
	for _, c := range cases {
		if got := st.ignored(c.path, c.dir); got != c.want {
			t.Errorf("ignored(%q, dir=%v) = %v, want %v", c.path, c.dir, got, c.want)
		}
	}
}

func TestNestedGitignoreBase(t *testing.T) {
	st := ignoreStack{
		parseIgnore("", "*.tmp\n"),
		parseIgnore("pkg", "/local.txt\n!important.tmp\n"),
	}
	if !st.ignored("pkg/local.txt", false) {
		t.Error("pkg/local.txt should be ignored by pkg/.gitignore")
	}
	if st.ignored("local.txt", false) {
		t.Error("root local.txt must not match pkg's anchored rule")
	}
	if st.ignored("pkg/important.tmp", false) {
		t.Error("negation in nested file should win")
	}
	if !st.ignored("other/important.tmp", false) {
		t.Error("negation must only apply under pkg/")
	}
}

func TestAlwaysFlag(t *testing.T) {
	for _, n := range []string{".env", ".env.production", "prod.env", ".envrc", ".mcp.json", ".dev.vars"} {
		if !alwaysFlag(n) {
			t.Errorf("%s should be scanned even when ignored", n)
		}
	}
	if alwaysFlag("main.go") {
		t.Error("main.go is not an env file")
	}
}

func TestSkipPathForGitHistory(t *testing.T) {
	skip := []string{".yarn/releases/yarn-4.9.2.cjs", "node_modules/x/index.js", "web/node_modules/a.js",
		"output/playwright/profile/Default/Preferences", "a/.com.google.Chrome.w1eUsR",
		".vscode/extensions/x/out/ext.js", "saved/Page_files/app.js"}
	keep := []string{"src/config.json", "packages/server/src/env.ts", ".env", "extensions/my-ext/src/index.ts"}
	for _, p := range skip {
		if !SkipPath(p) {
			t.Errorf("%s should be skipped", p)
		}
	}
	for _, p := range keep {
		if SkipPath(p) {
			t.Errorf("%s must be scanned", p)
		}
	}
}

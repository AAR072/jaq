package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxImagePinsStaticToolchainAndExcludesDynamicRuntimes(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "analysis", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"radare2-6.2.0.tar.xz",
		"098488a3a0a4c11b893ae9e74496cf65561d17cefd9b7f2661a48b4be97b663a",
		"d74b6b9855622c9a7070165b1961262afd686a3f",
		"org.opencontainers.image.r2mcp.version=\"1.8.6\"",
		"USER 65532:65532",
		"binutils binwalk build-essential",
		"Python-${PYTHON314_VERSION}.tar.xz",
		"3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81",
		"requirements-static.txt",
		"pyinstxtractor-ng pydisasm readpe upx yara",
		"JAQ_TOOLS_MANIFEST=/opt/jaq/TOOLS.md",
		"--disable-debugger --without-ptrace-wrap --disable-loadlibs",
		"--without-qjs",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("Dockerfile missing %q", required)
		}
	}
	for _, forbidden := range []string{"apt-get install wine", "mono-runtime", "qemu-system", "unicorn==", "speakeasy==", "qiling==", "frida=="} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("Dockerfile includes forbidden execution/emulation capability %q", forbidden)
		}
	}
}

func TestStaticToolInventoryAndPythonDisassemblerAreNonExecuting(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join("..", "..", "analysis", "TOOLS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	for _, required := range []string{
		"pyinstxtractor-ng", "pyc-disasm", "Python 3.14", "dnfile", "dncil",
		"capa", "binwalk", "readpe", "llvm-pdbutil", "pycryptodome",
		"never execute, import, load as a native library, emulate, or",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("TOOLS.md missing %q", required)
		}
	}
	disassembler, err := os.ReadFile(filepath.Join("..", "..", "analysis", "pyc-disasm"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(disassembler)
	for _, required := range []string{"marshal.loads", "dis.dis", "types.CodeType", "--raw", "--offset", "MAX_INPUT_BYTES", "MAX_CODE_OBJECTS"} {
		if !strings.Contains(source, required) {
			t.Errorf("pyc-disasm missing %q", required)
		}
	}
	for _, forbidden := range []string{"exec(", "eval(", "subprocess", "runpy", "import_module("} {
		if strings.Contains(source, forbidden) {
			t.Errorf("pyc-disasm contains execution primitive %q", forbidden)
		}
	}
	if strings.Contains(string(manifest), "- `floss`") {
		t.Error("TOOLS.md advertises FLOSS even though emulation is out of scope")
	}
	if strings.Contains(string(manifest), "- `binref`") {
		t.Error("TOOLS.md advertises Binary Refinery even though it includes execution units")
	}
}

func TestSandboxEntrypointOnlyKeepsControllerSessionAlive(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "analysis", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	if !strings.Contains(text, "sleep infinity") {
		t.Fatal("entrypoint does not preserve the controller-owned session")
	}
	for _, forbidden := range []string{"sample.exe", "r2 ", "r2mcp", "python", "objdump", "curl", "wget"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("entrypoint performs analysis/network action %q", forbidden)
		}
	}
}

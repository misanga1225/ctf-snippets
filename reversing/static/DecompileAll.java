// @desc:  Ghidra ヘッドレス用ポストスクリプト（全関数 or 名前一致の関数を逆コンパイルして 1 つの C ファイルに出力）
// @tags:  ctf, reversing, static, ghidra, decompile, headless, script
// @deps:  Ghidra 10 以上（ghidra_decompile.sh から呼ばれる）
// @usage: analyzeHeadless /tmp/proj p -import ./chall -scriptPath reversing/static -postScript DecompileAll.java out.c [filter] -deleteProject
//
// 引数: [0] 出力ファイル（省略時 <プログラム名>.c） [1] 関数名の部分一致フィルタ（省略時は全関数）
// ライブラリ関数（外部関数・サンク）はスキップする。

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 && !args[0].isEmpty() ? args[0] : currentProgram.getName() + ".c";
        String filter = args.length > 1 ? args[1] : "";

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        int ok = 0, failed = 0;
        try (PrintWriter pw = new PrintWriter(new FileWriter(out))) {
            pw.printf("// %s  (image base %s)%n", currentProgram.getName(), currentProgram.getImageBase());
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal() || f.isThunk() || !f.getName().contains(filter)) {
                    continue;
                }
                DecompileResults r = ifc.decompileFunction(f, 60, monitor);
                pw.printf("%n// ===== %s @ %s =====%n", f.getName(), f.getEntryPoint());
                if (r != null && r.decompileCompleted()) {
                    pw.println(r.getDecompiledFunction().getC());
                    ok++;
                } else {
                    pw.printf("// decompile failed: %s%n", r == null ? "null" : r.getErrorMessage());
                    failed++;
                }
            }
        } finally {
            ifc.dispose();
        }
        println(String.format("DecompileAll: %d functions -> %s (failed %d)", ok, out, failed));
    }
}

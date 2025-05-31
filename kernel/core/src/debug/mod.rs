pub mod serial; 

fn print_symbolicated_backtrace() {
    // スタックバックトレースを取得し、シンボル情報を付加して表示
    // 1. 現在のスタックポインタとフレームポインタを取得する (アーキテクチャ依存の方法で)。
    // 2. スタックを巻き戻し (get_backtrace関数を利用)、リターンアドレスのリストを収集する。
    // 3. 各リターンアドレスに対応するシンボル名（関数名、ファイル名、行番号）を検索する。
    //    これにはデバッグ情報（例: DWARFフォーマットのデバッグセクション）の解析が必要。
    //    - カーネルイメージやロードされたモジュールからデバッグ情報を読み込む。
    //    - アドレスからシンボル情報へのマッピングを行う。
    // TODO: デバッグシンボル情報 (例: ELFファイルの .debug_info, .debug_line, .debug_str セクションなど) を
    //       ロード・解析する機能を実装する。
    //       `gimli` クレート (DWARFパーサー) や `addr2line` クレート (アドレスからファイル名/行番号への変換) の
    //       利用を検討する。カーネルシンボルテーブルの管理も必要。
    //       シンボルが見つからない場合や、インライン化された関数の扱いも考慮すること。
    log::info!("--- Backtrace ---");
    // for frame in get_backtrace(16) { // 例えば最大16フレーム
    //     if let Some(symbol) = lookup_symbol(frame.instruction_pointer) {
    //         log::info!("  {:#x}: {} ({}:{})", frame.instruction_pointer, symbol.name, symbol.file, symbol.line);
    //     } else {
    //         log::info!("  {:#x}: <unknown symbol or no debug info>", frame.instruction_pointer);
    //     }
    // }
    log::warn!("Symbolicated backtrace is not fully implemented.");
}

fn get_backtrace(max_frames: usize) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    // 実際のスタック巻き戻し処理 (アーキテクチャ依存)
    // 1. 現在のフレームポインタ (FP) とスタックポインタ (SP) を取得する。
    //    - x86_64では RBP (FP) と RSP (SP)。AArch64では FP (X29) と SP (X31)。
    // 2. FPが指すスタック上の場所に、前のFPの値とリターンアドレスが保存されていると仮定する (標準的なスタックフレーム規約)。
    //    - `[FP]` に古いFPの値、`[FP + sizeof(pointer)]` にリターンアドレス。
    // 3. ループでスタックを遡る:
    //    a. 現在のFPからリターンアドレスを読み取り、StackFrameとして保存。
    //    b. 現在のFPから古いFPの値を読み取り、それを新しいFPとする。
    //    c. FPがヌルになるか、スタックの境界を超えた場合、またはmax_framesに達したら終了。
    // TODO: アーキテクチャ固有のスタック巻き戻しロジックを実装する。
    //       - フレームポインタが省略されている場合 (最適化ビルドなど) の対応も考慮が必要 (例: DWARFの.eh_frameを利用)。
    //       - スタックの破損や不正なフレームポインタに対する堅牢なエラーハンドリングを実装する。
    //       - `max_frames` を超えた場合の処理。
    //       - カーネルスタックとユーザースタックの境界を意識する。

    // ダミー実装: 現在の関数のみ示す (実際には呼び出し履歴を遡る)
    // frames.push(StackFrame { instruction_pointer: print_symbolicated_backtrace as usize, symbol_name: None });
    frames
} 
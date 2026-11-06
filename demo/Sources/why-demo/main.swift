// why-demo: one crash per `why` rule, picked by the first argument.
//
//     swift build --package-path demo
//     lldb -o run -k why -- demo/.build/debug/why-demo <scenario>
//
// Every scenario is written the way the bug tends to appear in real code,
// not as the shortest possible crash.

import Dispatch
import Foundation
import LegacyAPI

// MARK: - Scenarios

let scenarios: [(name: String, summary: String, run: () -> Void)] = [
    ("nil-pointer", "C API declared nonnull returns NULL; Swift reads a field at offset 0x28", nilPointer),
    ("recursion", "infinite recursion on a 512 KB secondary thread (iOS default)", { onThread(stackSize: 512 << 10, recursion) }),
    ("recursion-main", "infinite recursion on the main thread (8 MB on macOS)", recursion),
    ("big-enum", "deep view-like chain copying a 7.6 KB enum by value, on a 1 MB stack (iOS main thread)",
     { onThread(stackSize: 1 << 20, bigEnum) }),
    ("use-after-free", "over-release through Unmanaged", useAfterFree),
    ("bad-function-pointer", "calls a C function pointer made from a bad integer", badFunctionPointer),
    ("force-unwrap", "force unwrap of a nil Optional", forceUnwrap),
    ("index-out-of-range", "array index past the end", indexOutOfRange),
    ("overflow", "integer overflow", overflow),
    ("fatal-error", "fatalError() with a custom message", fatalErrorScenario),
    ("actor-isolation", "@MainActor closure called on a background queue by a C API", actorIsolation),
    ("nsexception", "uncaught NSRangeException from NSArray", nsException),
    ("write-constant", "writes through a pointer into a string literal", writeConstant),
    ("corrupt-pointer", "dereferences a pointer with garbage high bits", corruptPointer),
    ("double-free", "frees the same malloc block twice", doubleFree),
    ("dispatch-sync-main", "DispatchQueue.main.sync from the main thread", dispatchSyncMain),
    ("abort", "calls abort() after logging", abortScenario),
]

// MARK: EXC_BAD_ACCESS

func nilPointer() {
    // legacy_find_header is annotated _Nonnull, so Swift imports it as non-optional.
    let header = legacy_find_header("missing")
    print("records:", header.pointee.count)   // count is at offset 0x28
}

@inline(never) func countDown(_ n: Int) -> Int {
    // Forgot the base case.
    return countDown(n - 1) + 1
}

func recursion() {
    print(countDown(10))
}

/// Shaped like the case that motivated `why`: a list item whose trailing
/// content enum has one huge payload, so every copy of the enum costs ~7.6 KB
/// of stack, and the compiler-generated "outlined init with copy" helper
/// needs a frame big enough to call ___chkstk_darwin.
struct ListItem {
    struct Stats { var a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0 }       // 64 B
    struct Panel { var s0 = Stats(), s1 = Stats(), s2 = Stats(), s3 = Stats(),
                   s4 = Stats(), s5 = Stats(), s6 = Stats(), s7 = Stats() }            // 512 B
    struct Scoreboard {                                                                  // 7.5 KB
        var p0 = Panel(), p1 = Panel(), p2 = Panel(), p3 = Panel(), p4 = Panel()
        var p5 = Panel(), p6 = Panel(), p7 = Panel(), p8 = Panel(), p9 = Panel()
        var p10 = Panel(), p11 = Panel(), p12 = Panel(), p13 = Panel(), p14 = Panel()
    }
    enum EndContent {
        case none
        case badge(String)
        case scoreboard(Scoreboard, title: String)   // the enum is as big as this payload
    }

    var title: String
    var end: EndContent?
}

@inline(never) func sectionBody(_ items: [ListItem], depth: Int) -> Int {
    rowBody(items[depth % items.count], items, depth: depth)
}

@inline(never) func rowBody(_ item: ListItem, _ items: [ListItem], depth: Int) -> Int {
    let trailing = item.end           // copies EndContent? by value
    return cardBody(item, trailing, items, depth: depth)
}

@inline(never) func cardBody(_ item: ListItem, _ trailing: ListItem.EndContent?, _ items: [ListItem], depth: Int) -> Int {
    let shown = trailing              // and again
    if case .scoreboard(let board, _)? = shown, depth > 100_000 { return board.p0.s0.a }
    return sectionBody(items, depth: depth + 1) + item.title.count
}

func bigEnum() {
    let items = (0..<4).map { ListItem(title: "Match \($0)", end: .scoreboard(.init(), title: "Live")) }
    print(sectionBody(items, depth: 0))
}

final class Session {
    var token = "secret"
}

func useAfterFree() {
    let session = Unmanaged.passRetained(Session())
    session.release()          // balances passRetained: the Session is freed here
    // ... later, code that still holds the Unmanaged reference:
    session.release()
    session.release()
    print(session.takeUnretainedValue().token)
}

func badFunctionPointer() {
    typealias Callback = @convention(c) () -> Void
    let stored: Int = 0x1_2345_6780          // e.g. read from a corrupted struct
    let callback = unsafeBitCast(stored, to: Callback.self)
    callback()
}

func writeConstant() {
    let greeting: StaticString = "hello, constant world"
    let bytes = UnsafeMutablePointer(mutating: greeting.utf8Start)
    bytes[0] = UInt8(ascii: "H")              // string literals live in read-only __TEXT
}

func corruptPointer() {
    let raw = UInt(0x4141_4141_4141_4148)    // e.g. bytes of a string where a pointer was expected
    let pointer = UnsafePointer<Int>(bitPattern: raw)!
    print(pointer.pointee)
}

func doubleFree() {
    let buffer = malloc(64)
    free(buffer)
    free(buffer)
}

// MARK: Swift runtime traps

func forceUnwrap() {
    let settings: [String: String] = ["theme": "dark"]
    let fontSize = settings["fontSize"]!     // nil
    print(fontSize)
}

func indexOutOfRange() {
    let scores = [10, 20, 30]
    let last = scores.count                   // off by one
    print(scores[last])
}

func overflow() {
    var total: Int8 = 120
    for bonus in [5, 10] { total += Int8(bonus) }
    print(total)
}

func fatalErrorScenario() {
    fatalError("Unsupported configuration: \(CommandLine.arguments.count) arguments")
}

@MainActor final class ScoreViewModel {
    var refreshes = 0

    func startRefreshing() {
        // This closure is written in a @MainActor context and the C API doesn't
        // say its block is @Sendable, so Swift 6 infers it @MainActor and checks
        // that at runtime, but the API runs it on a background queue.
        legacy_run_on_background {
            self.refreshes += 1
        }
    }
}

func actorIsolation() {
    MainActor.assumeIsolated { ScoreViewModel().startRefreshing() }
    dispatchMain()
}

func dispatchSyncMain() {
    DispatchQueue.main.sync { print("never runs") }
}

// MARK: Aborts

func nsException() {
    let ids = NSArray(array: ["a"])
    print(ids.object(at: 3))
}

func abortScenario() {
    fputs("fatal: database schema version 7 is newer than this build supports\n", stderr)
    abort()
}

// MARK: - Helpers

/// Runs `body` on a thread with the given stack size, so stack sizes match iOS.
func onThread(stackSize: Int, _ body: @escaping @Sendable () -> Void) {
    let thread = Thread(block: body)
    thread.stackSize = stackSize
    thread.start()
    while true { sleep(1) }
}

// MARK: - Main

let arguments = CommandLine.arguments
guard arguments.count > 1, let scenario = scenarios.first(where: { $0.name == arguments[1] }) else {
    print("usage: why-demo <scenario>\n")
    for s in scenarios { print("  \(s.name.padding(toLength: 22, withPad: " ", startingAt: 0)) \(s.summary)") }
    exit(arguments.count > 1 ? 2 : 0)
}
scenario.run()
print("scenario \(scenario.name) did not crash")
exit(1)

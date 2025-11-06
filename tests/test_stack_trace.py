from __future__ import annotations

from pathlib import Path

from scanner.definitions import PROJECT_ROOT
from scanner.modules.error.error_leak import _detect_stack_traces_for_body
from scanner.modules.error.stack_trace_signatures import STACKTRACE_SIGNATURES

JS_TRACES = [
"""
/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_simple.js:2
  throw new Error("simple boom");
  ^

Error: simple boom
    at boom (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_simple.js:2:9)
    at Object.<anonymous> (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_simple.js:5:1)
    at Module._compile (node:internal/modules/cjs/loader:1529:14)
    at Module._extensions..js (node:internal/modules/cjs/loader:1613:10)
    at Module.load (node:internal/modules/cjs/loader:1275:32)
    at Module._load (node:internal/modules/cjs/loader:1096:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:164:12)
    at node:internal/main/run_main_module:28:49

Node.js v20.19.1
""",

"""
/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_type.js:3
  return x.toString(); // TypeError
           ^

TypeError: Cannot read properties of null (reading 'toString')
    at level3 (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_type.js:3:12)
    at level2 (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_type.js:7:10)
    at level1 (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_type.js:11:10)
    at Object.<anonymous> (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_type.js:14:1)
    at Module._compile (node:internal/modules/cjs/loader:1529:14)
    at Module._extensions..js (node:internal/modules/cjs/loader:1613:10)
    at Module.load (node:internal/modules/cjs/loader:1275:32)
    at Module._load (node:internal/modules/cjs/loader:1096:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:164:12)
    at node:internal/main/run_main_module:28:49

Node.js v20.19.1
""",

"""
/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_async.js:2
  throw new Error("async boom");
        ^

Error: async boom
    at bad (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_async.js:2:9)
    at Object.<anonymous> (/home/isaac/Projects/Website-Scanner/tests/res/stack_traces/error_async.js:5:1)
    at Module._compile (node:internal/modules/cjs/loader:1529:14)
    at Module._extensions..js (node:internal/modules/cjs/loader:1613:10)
    at Module.load (node:internal/modules/cjs/loader:1275:32)
    at Module._load (node:internal/modules/cjs/loader:1096:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:164:12)
    at node:internal/main/run_main_module:28:49

Node.js v20.19.1
"""

]

PY_TRACES = [
"""
/home/isaac/Projects/Website-Scanner/tests/py_error_async.py:9: RuntimeWarning: coroutine 'handler' was never awaited
  handler()
RuntimeWarning: Enable tracemalloc to get the object allocation traceback

""",

"""
Traceback (most recent call last):
  File "/home/isaac/Projects/Website-Scanner/tests/py_error_index.py", line 7, in <module>
    get_user(users, 5)
  File "/home/isaac/Projects/Website-Scanner/tests/py_error_index.py", line 2, in get_user
    return users[index]
           ~~~~~^^^^^^^
IndexError: list index out of range
""",

"""
  File "/home/isaac/Projects/Website-Scanner/tests/py_error_simple.py", line 1
SyntaxError: invalid character '┌' (U+250C)
""",

"""
Traceback (most recent call last):
  File "/home/isaac/Projects/Website-Scanner/tests/py_error_unhandled.py", line 11, in <module>
    handle_client()
  File "/home/isaac/Projects/Website-Scanner/tests/py_error_unhandled.py", line 8, in handle_client
    process_request(request)
  File "/home/isaac/Projects/Website-Scanner/tests/py_error_unhandled.py", line 3, in process_request
    raise ValueError("Request must be a dictionary")
ValueError: Request must be a dictionary
""",
]

JAVA_TRACES = [
"""
Exception in thread "main" java.lang.NullPointerException: Cannot invoke "String.length()" because "<local1>" is null
	at NullPointerDemo.main(NullPointerDemo.java:5)
""",

"""
Exception in thread "main" MyCustomException: Boom from third()
	at CustomExceptionDemo.third(CustomExceptionDemo.java:22)
	at CustomExceptionDemo.second(CustomExceptionDemo.java:18)
	at CustomExceptionDemo.first(CustomExceptionDemo.java:14)
	at CustomExceptionDemo.main(CustomExceptionDemo.java:10)

""",

"""
Exception in thread "main" java.lang.ArrayIndexOutOfBoundsException: Index 10 out of bounds for length 3
	at ArrayIndexDemo.main(ArrayIndexDemo.java:5)
""",

"""
Exception in thread "main" java.lang.ArithmeticException: / by zero
	at Helper.parseAndDivide(Helper.java:5)
	at HelperExceptionDemo.main(HelperExceptionDemo.java:4)
""",

"""
Exception in thread "main" java.lang.StackOverflowError
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
	at StackOverflowDemo.recurse(StackOverflowDemo.java:9)
"""
]

GO_TRACES = [
"""
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x491b32]

goroutine 1 [running]:
main.main()
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/nil_ptr.go:12 +0x52
exit status 2
""",

"""
panic: runtime error: index out of range [10] with length 3

goroutine 1 [running]:
main.main()
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/idx_err.go:9 +0x7c
exit status 2
""",

"""
panic: runtime error: integer divide by zero

goroutine 1 [running]:
main.main()
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/div_by_zero.go:9 +0x4b
exit status 2
""",

"""
panic: boom from third()

goroutine 1 [running]:
main.third(...)
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/nested_panic.go:12
main.second(...)
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/nested_panic.go:8
main.first(...)
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/nested_panic.go:4
main.main()
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/nested_panic.go:16 +0x25
exit status 2
""",

"""
panic: panic inside goroutine

goroutine 6 [running]:
main.worker()
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/panic_in_go_route.go:10 +0x59
created by main.main in goroutine 1
	/home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/go/panic_in_go_route.go:14 +0x1a
exit status 2
"""
]

RUBY_TRACES = [
"""
no_method_nil.rb:3:in `fetch_user_name': undefined method `[]' for nil (NoMethodError)

  user[:name]  # will blow up if user is nil
      ^^^^^^^
	from no_method_nil.rb:9:in `main'
	from no_method_nil.rb:12:in `<main>'
""",

"""
zero_div.rb:3:in `/': divided by 0 (ZeroDivisionError)
	from zero_div.rb:3:in `divide'
	from zero_div.rb:8:in `main'
	from zero_div.rb:11:in `<main>'
About to divide by zero...
""",

"""
nested_exception.rb:5:in `charge_card': Declined payment for 5000 cents (PaymentError)
	from nested_exception.rb:9:in `process_order'
	from nested_exception.rb:13:in `main'
	from nested_exception.rb:16:in `<main>'
""",

"""
wrong_arity.rb:2:in `send_email': wrong number of arguments (given 1, expected 2) (ArgumentError)
	from wrong_arity.rb:8:in `main'
	from wrong_arity.rb:11:in `<main>'
""",

"""
missing_file.rb:3:in `read': No such file or directory @ rb_sysopen - this_config_does_not_exist.yml (Errno::ENOENT)
	from missing_file.rb:3:in `read_config'
	from missing_file.rb:8:in `main'
	from missing_file.rb:11:in `<main>'
"""
]

PHP_TRACES = [
"""
PHP Fatal error:  Uncaught Error: Call to undefined function does_not_exist() in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/undefined_fun.php:6
Stack trace:
#0 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/undefined_fun.php(9): controller()
#1 {main}
  thrown in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/undefined_fun.php on line 6
""",

"""
PHP Fatal error:  Uncaught PaymentException: Declined payment for 5000 cents in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/nested_exception.php:7
Stack trace:
#0 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/nested_exception.php(11): chargeCard()
#1 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/nested_exception.php(15): processOrder()
#2 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/nested_exception.php(18): main()
#3 {main}
  thrown in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/nested_exception.php on line 7
""",

"""
PHP Fatal error:  Uncaught TypeError: sendEmail(): Argument #1 ($to) must be of type string, array given, called in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php on line 10 and defined in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php:4
Stack trace:
#0 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php(10): sendEmail()
#1 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php(13): main()
#2 {main}
  thrown in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php on line 4
""",

"""
About to divide by zero...
PHP Fatal error:  Uncaught DivisionByZeroError: Division by zero in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/div_by_zero.php:5
Stack trace:
#0 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/div_by_zero.php(5): intdiv()
#1 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/div_by_zero.php(10): divide()
#2 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/div_by_zero.php(13): main()
#3 {main}
  thrown in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/div_by_zero.php on line 5
""",

"""
PHP Fatal error:  Uncaught Error: Class "PDO" not found in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php:11
Stack trace:
#0 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php(18): connect()
#1 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php(22): main()
#2 {main}
  thrown in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php on line 11
""",

"""
Uncaught PDOException: could not find driver in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php:11 Stack trace: #0 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php(11): PDO->__construct() #1 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php(18): connect() #2 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php(22): main() #3 {main} thrown in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/db_err.php on line 11
""",

"""
PHP Fatal error:  Uncaught TypeError: sendEmail(): Argument #1 ($to) must be of type string, array given, called in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php on line 10 and defined in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php:4
Stack trace:
#0 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php(10): sendEmail()
#1 /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php(13): main()
#2 {main}
  thrown in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/php/type_error.php on line 4
"""
 ]


CS_TRACES = [
"""
Simulating service-layer null reference...
Unhandled exception. System.NullReferenceException: Object reference not set to an instance of an object.
   at DotNetErrorSamples.UserService.GetDisplayName(Int32 id) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 21
   at DotNetErrorSamples.Program.Main(String[] args) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 11
""",

"""
Simulating invalid query parameter...
Unhandled exception. System.ArgumentException: Order id must be a non-empty string. (Parameter 'id')
   at DotNetErrorSamples.OrderRepository.GetOrderById(String id) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 21
   at DotNetErrorSamples.Program.Main(String[] args) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 11
""",

"""
Simulating misconfigured dependency...
Unhandled exception. System.InvalidOperationException: SMTP host is not configured.
   at DotNetErrorSamples.EmailSender.SendWelcomeEmail(String to) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 40
   at DotNetErrorSamples.Program.Main(String[] args) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 13
""",

"""
Simulating bad GUID in route or query string...
Unhandled exception. System.FormatException: Unrecognized Guid format.
   at System.Guid.GuidResult.SetFailure(ParseFailure failureKind)
   at System.Guid.TryParseGuid(ReadOnlySpan`1 guidString, GuidResult& result)
   at System.Guid.Parse(ReadOnlySpan`1 input)
   at System.Guid.Parse(String input)
   at DotNetErrorSamples.Program.HandleRequest(String requestId) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 16
   at DotNetErrorSamples.Program.Main(String[] args) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 10
""",

"""
Simulating downstream HTTP API failure...
Unhandled exception. System.UriFormatException: Invalid URI: Invalid port specified.
   at System.Uri.CreateThis(String uri, Boolean dontEscape, UriKind uriKind, UriCreationOptions& creationOptions)
   at System.Uri..ctor(String uriString, UriKind uriKind)
   at System.Net.Http.HttpClient.CreateUri(String uri)
   at System.Net.Http.HttpClient.GetAsync(String requestUri)
   at DotNetErrorSamples.Program.CallDownstreamApiAsync() in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 23
   at DotNetErrorSamples.Program.Main(String[] args) in /home/isaac/Projects/Website-Scanner/tests/res/stack_trace_generators/c_sharp_net/DotNetErrorSamples/Program.cs:line 12
   at DotNetErrorSamples.Program.<Main>(String[] args)
"""
]


def _js_signature():
    for sig in STACKTRACE_SIGNATURES:
        if sig.language == "javascript":
            return sig
    raise AssertionError("JavaScript stack trace signature not found")


def _py_signature():
    for sig in STACKTRACE_SIGNATURES:
        if sig.language == "python":
            return sig
    raise AssertionError("Python stack trace signature not found")


def test_js_stacktrace_detects_real_traces():
    sig = _js_signature()

    for trace in JS_TRACES:
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=trace,
            stack_traces=[sig],
        )
        assert len(rows) == 1
        hit = rows[0]
        assert hit.language == "javascript"
        assert "Error" in hit.first_line or "TypeError" in hit.first_line
        assert hit.frame_count >= 1


def test_py_stacktrace_detects_real_traces():
    sig = _py_signature()

    for trace in PY_TRACES:
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=trace,
            stack_traces=[sig],
        )
        assert len(rows) >= 1, f"Expected Python detection for:\n{trace}"
        for hit in rows:
            assert hit.language == "python"
            assert hit.frame_count >= 1


def test_js_stacktrace_no_false_positive_in_example_html():
    sig = _js_signature()

    html_dir = PROJECT_ROOT / "tests" / "res" / "example_html"
    for idx in range(3):
        path: Path = html_dir / f"file_{idx}.html"
        assert path.exists(), f"Missing HTML fixture: {path}"

        text = path.read_text(encoding="utf-8")
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=text,
            stack_traces=[sig],
        )
        assert rows == [], f"Unexpected JS stack trace detected in {path}"


def test_py_stacktrace_no_false_positive_in_example_html():
    sig = _py_signature()

    html_dir = PROJECT_ROOT / "tests" / "res" / "example_html"
    for idx in range(3):
        path: Path = html_dir / f"file_{idx}.html"
        assert path.exists(), f"Missing HTML fixture: {path}"

        text = path.read_text(encoding="utf-8")
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=text,
            stack_traces=[sig],
        )
        assert rows == [], f"Unexpected Python stack trace detected in {path}"

def _java_signature():
    for sig in STACKTRACE_SIGNATURES:
        if sig.language == "java":
            return sig
    raise AssertionError("Java stack trace signature not found")

def test_java_stacktrace_detects_real_traces():
    sig = _java_signature()

    for trace in JAVA_TRACES:
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=trace,
            stack_traces=[sig],
        )
        assert len(rows) >= 1, f"Expected Java detection for:\n{trace}"
        for hit in rows:
            assert hit.language == "java"
            assert hit.frame_count >= 1


def test_java_stacktrace_no_false_positive_in_example_html():
    sig = _java_signature()

    html_dir = PROJECT_ROOT / "tests" / "res" / "example_html"
    for idx in range(3):
        path: Path = html_dir / f"file_{idx}.html"
        assert path.exists(), f"Missing HTML fixture: {path}"

        text = path.read_text(encoding="utf-8")
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=text,
            stack_traces=[sig],
        )
        assert rows == [], f"Unexpected Java stack trace detected in {path}"


def _go_signature():
    for sig in STACKTRACE_SIGNATURES:
        if sig.language == "go":
            return sig
    raise AssertionError("Go stack trace signature not found")


def test_go_stacktrace_detects_real_traces():
    sig = _go_signature()

    for trace in GO_TRACES:
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=trace,
            stack_traces=[sig],
        )
        assert len(rows) >= 1, f"Expected Go detection for:\n{trace}"
        for hit in rows:
            assert hit.language == "go"
            assert hit.frame_count >= 1


def test_go_stacktrace_no_false_positive_in_example_html():
    sig = _go_signature()

    html_dir = PROJECT_ROOT / "tests" / "res" / "example_html"
    for idx in range(3):
        path: Path = html_dir / f"file_{idx}.html"
        assert path.exists(), f"Missing HTML fixture: {path}"

        text = path.read_text(encoding="utf-8")
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=text,
            stack_traces=[sig],
        )
        assert rows == [], f"Unexpected Go stack trace detected in {path}"


def _ruby_signature():
    for sig in STACKTRACE_SIGNATURES:
        if sig.language == "ruby":
            return sig
    raise AssertionError("Ruby stack trace signature not found")



def test_ruby_stacktrace_detects_real_traces():
    sig = _ruby_signature()

    for trace in RUBY_TRACES:
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=trace,
            stack_traces=[sig],
        )
        assert len(rows) >= 1, f"Expected Ruby detection for:\n{trace}"
        for hit in rows:
            assert hit.language == "ruby"
            assert hit.frame_count >= 1

def test_ruby_stacktrace_no_false_positive_in_example_html():
    sig = _ruby_signature()

    html_dir = PROJECT_ROOT / "tests" / "res" / "example_html"
    for idx in range(3):
        path: Path = html_dir / f"file_{idx}.html"
        assert path.exists(), f"Missing HTML fixture: {path}"

        text = path.read_text(encoding="utf-8")
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=text,
            stack_traces=[sig],
        )
        assert rows == [], f"Unexpected Ruby stack trace detected in {path}"

def _php_signature():
    for sig in STACKTRACE_SIGNATURES:
        if sig.language == "php":
            return sig
    raise AssertionError("PHP stack trace signature not found")

def test_php_stacktrace_detects_real_traces():
    sig = _php_signature()

    for trace in PHP_TRACES:
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=trace,
            stack_traces=[sig],
        )
        assert len(rows) >= 1, f"Expected PHP detection for:\n{trace}"
        for hit in rows:
            assert hit.language == "php"
            assert hit.frame_count >= 1

def test_php_stacktrace_no_false_positive_in_example_html():
    sig = _php_signature()

    html_dir = PROJECT_ROOT / "tests" / "res" / "example_html"
    for idx in range(3):
        path: Path = html_dir / f"file_{idx}.html"
        assert path.exists(), f"Missing HTML fixture: {path}"

        text = path.read_text(encoding="utf-8")
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=text,
            stack_traces=[sig],
        )
        assert rows == [], f"Unexpected PHP stack trace detected in {path}"


def _csharp_signature():
    for sig in STACKTRACE_SIGNATURES:
        if sig.language == "csharp":
            return sig
    raise AssertionError("C#/.NET stack trace signature not found")


def test_csharp_stacktrace_detects_real_traces():
    sig = _csharp_signature()

    for trace in CS_TRACES:
        print(trace)
        rows = _detect_stack_traces_for_body(
            origin="example.com",
            body=trace,
            stack_traces=[sig],
        )
        assert len(rows) >= 1, f"Expected C#/.NET detection for:\n{trace}"
        for hit in rows:
            assert hit.language == "csharp"
            assert hit.frame_count >= 1




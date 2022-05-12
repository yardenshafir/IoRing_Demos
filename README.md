# IoRing_Demos
A repository for I/O ring demos, use cases and performance testing on Windows

Overview of I/O ring on Windows: https://windows-internals.com/i-o-rings-when-one-i-o-operation-is-not-enough  
I/O ring changes in 22H2: https://windows-internals.com/one-year-to-i-o-ring-what-changed/  
Comparison with Linux io_uring: https://windows-internals.com/ioring-vs-io_uring-a-comparison-of-windows-and-linux-implementations/  
MSDN documentation: https://docs.microsoft.com/en-us/windows/win32/api/ioringapi/nf-ioringapi-createioring  

# Projects in the Repository:
## IoRingPerf
A project to measure performance of I/O operations on Windows using different I/O mechanisms: synchronous, asynchronous, I/O Ring using NT API, I/O Ring using Win32 API
Some initial results when using this script and comparing the different I/O mechanisms:
| ReadFile  | ReadFileEx | I/O Ring Win32 API | I/O Ring NT API |
| ------------- | ------------- | ------------- | ------------- |
| 24600140797 | 23775522267 | 22698235147 | 22419537722 |
| 20453198839 | 20413611694 | 19932095776 | 19735951191 |
| 20623863171 | 20225322101 | 20222548679 | 20185793675 |
| 20346912325 | 20201343017 | 20017837622 | 20002724133 |

Results represent time in milliseconds needed to read ~4000 files using the specified I/O method and read all their bytes.
On average, I/O rings are ~2% faster than I/O ports and ~3% faster than synchronous read.
I took the most conservative results here since the measurements can change depending on file caching and other factors. Other testing showed improvement of up to 5-10% when using I/O rings compared to synchronous read.

## IoRingUserCompletionEvent
Shows the use of the 22H1 UserCompletionEvent to get notified on any new operation being completed and process results immediately.

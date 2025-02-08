
# Anti-Debugging Techniques in JNI(Java Native Interface)

This repository contains a C program in JNI(Java Native Interface) demonstrating various anti-debugging techniques. These techniques are designed to prevent or hinder the debugging of the program, making it more difficult for unauthorized users to analyze or reverse engineer the software.

## Features

- **Virtual Machine Detection**: Checks if the program is running inside a virtual machine by examining the Local Descriptor Table (LDT).
- **Debugger Presence Check**: Detects if a debugger is currently attached to the process.
- **Memory Dump Prevention**: Attempts to prevent memory dumps by changing the memory protection of the process.
- **Remote Debugging Prevention**: Blocks remote debugging by modifying process information.
- **Thread Injection Prevention**: Prevents thread injection attacks by modifying memory protection.
- **JDWP Interface Monitoring**: Monitors and disables the Java Debug Wire Protocol (JDWP) to prevent remote attachments.

## Customize

It's easy to combine this project into your project to protect your project from unauthorized debugging.

## Compilation

To compile this program, you will need a C compiler that supports Windows API functions, such as MinGW or Microsoft Visual C++. You can compile the program using the following command:

```bash
g++ -shared -I"%JAVA_HOME%\include" -I"%JAVA_HOME%\include\win32" antidebug.c -o antidebug.dll
```

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

## Recommendation

It is recommended to use **additional code virtualization/obfuscation** on your Java project.

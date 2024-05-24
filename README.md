# RWX_MEMEORY_HUNT_AND_INJECTION_DV
Abusing Windows fork API and OneDrive.exe process to inject the malicious shellcode without allocating new RWX memory region. This technique is finding RWX region in already running processes in this case OneDrive.exe and Write shellcode into that region and execute it without calling CreateRemoteThread, NtCreateRemoteThread or Direct calls. 

## Usage 
Just compile the program and run the (EXE) without any paremeter.

## Steps
* Find the OneDrive.exe in running processes.
* Get the handle of OneDrive.exe.
* Query remote process memory information.
* look for RWX memory regions.
* Write shellcode into found region of OneDrive.exe
* Fork OneDrive.exe into a new process.
* Set the forked process's start address to the cloned shellcode.
* Terminate the cloned process after execution.

## Shellcode
This technique will work with ntdll based shellcode which is not dependent on any section. I used https://github.com/rainerzufalldererste/windows_x64_shellcode_template to generate my shellcode.

## Shellcode Creation
* Edit the shellcode template file funtion 'shellcode_template' according to instructions given on https://github.com/rainerzufalldererste/windows_x64_shellcode_template
* Compile the code and open .EXE file in any hex editor (HxD)
* Extract the .text section and use that in given project file.
* To extract the shellcode there are other methods also explained in the repository.



## Only for educational purposes.
### DEMO 
https://www.linkedin.com/posts/usman-sikander13_%3F%3F%3F-%3F%3F%3F%3F%3F%3F-activity-7196426924351488001-RXOk?utm_source=share&utm_medium=member_desktop


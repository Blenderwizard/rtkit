<h1 align="center" style="border-bottom: none; margin-bottom: 0;">
    rtkit: By <a href="https://github.com/Blenderwizard">Jolan "Blenderwizard" Rathelot</a>
</h1>

## What is this ?

rtkit is a Simple Linux Kernel Module, or LKM, rootkit that allows users to hide process, file and directories, grant a root shell, and hide itself the kernel mod list.

> **Warning**
>
> Use of this project is for **Educational / Testing purposes only**. Using it on **unauthorised machines** is **strictly forbidden**. If somebody is found to use it for **illegal / malicious intent**, author of the repo will **not** be held responsible.

> **Info**
>
> This Module has only been tested on linux kernel version 6.0.0. It should be compatable with most other versions.

### Resources

1. [TheXcellerator's LKM Blog](https://xcellerator.github.io/posts/linux_rootkits_01/)
2. [Ethical Hacking by Daniel G. Graham](https://nostarch.com/ethical-hacking)
3. ChatGPT ¯\\\_(ツ)_/¯

### Features

1. The ablility to hide any file or directory that start with a prefix, by default this prefix is `"rtkit_exclude"`. This prefix can be modified by changing `DIRECTORY_EXCLUSION_PREFIX` found in `include/rootkit_utils.h`.
2. The ablility to hide user definable process ids. Running `kill -66 <pid to hide>` hide the any running process with that pid. The number 66 can be changed by modifying `TOGGLE_PID_HIDE_SIGNAL_CODE` in `include/rootkit_utils.h`
3. The ability to hide or show the module from `lsmod`. Running `kill -65 <any number>` toggles it's visiblility. The number 65 can be changed by modifying `TOGGLE_MODULE_HIDE_SIGNAL_CODE` in `include/rootkit_utils.h`
4. The ablility to get a root shell. Running `kill -64 <any number>` grants you a root shell. The number 64 can be changed by modifying `ROOT_SHELL_SIGNAL_CODE` in `include/rootkit_utils.h`

## Install

Clone the repository and navigate to the root of the directory, to build and install the module, simply run `make` followed by `make install`. 

You will need to be a privelaged used on the system to run `make install`. 

Congrats the rootkit has been installed!

## Uninstall
To uninstall you need to unhide the module, the default to unhide the module command is `kill -65 1`. Then run `make uninstall`.



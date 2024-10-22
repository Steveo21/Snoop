# Snoop
Repository demonstrating API hashing with a pythonic hashing program that takes the string value of the API you want to hash as input. Refactored version of ired.team's C++ code for an example of implementation, snoop is a Python port of their hashing algorithm as well.

This is a learning POC! All credit to the author(s) of the blog's that fueled this project:

Primary reference for API Hashing:
https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware

Great Reading for the Resolution Functionality:

https://cocomelonc.github.io/malware/2023/04/16/malware-av-evasion-16.html

https://cocomelonc.github.io/malware/2023/04/08/malware-av-evasion-15.html


![snoop](https://github.com/user-attachments/assets/b4f652a6-9f11-45d3-9011-4dc42120cc90)


# Proof of Concept

Start by running snoop and passing it the name of the function you want to hash...

![image](https://github.com/user-attachments/assets/f12947c9-1020-4c9d-8d07-20fa7faf9d91)

Then, make the changes necessary in the example.cpp...

![image](https://github.com/user-attachments/assets/0724a1e1-83af-49fa-ac87-21ccaffdf030)
![image](https://github.com/user-attachments/assets/4ed40f28-2f24-4316-b487-386ec7138032)

Adjust parameters as needed for your use case.

To compile:
x86_64-w64-mingw32-g++ example.cpp -o example.exe -static

When run, we can see the example code works!

![image](https://github.com/user-attachments/assets/f0aea52c-3e6e-44d3-ab97-a16c131b5c68)






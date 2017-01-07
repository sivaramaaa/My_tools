<h1> Blind Format String Exploitation </h1>
<p>     This is a module to exploit blind format string vulnerability  </p>
<p> <b> Steps For Exploitation </b> </p>
<p> 1) leak the code </p>
<p> 2) leak Libc usinf pwntools Dynelf module </p>
<p> 3) leak .dynamic ptr and then GOT table addr </p>
<p> 4) leak printf_got </p>
<p> 5) Overwrite printf_got with system addr </p>
<p> 6) send /bin/sh </p>

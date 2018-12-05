![AutoRDPwn](https://user-images.githubusercontent.com/34335312/45109339-8b203580-b13f-11e8-9de7-1210114313bb.png)


**AutoRDPwn** es un script creado en Powershell y diseñado para automatizar el ataque **Shadow** en equipos Microsoft Windows. Esta vulnerabilidad permite a un atacante remoto visualizar el escritorio de su víctima sin su consentimiento, e incluso controlarlo a petición. Para su correcto funcionamiento, es necesario cumplir los requisitos que se describen en la guía de uso.


# Requisitos
Powershell 5.0 o superior


# Cambios

## Versión 4.5
• Nuevo icono estilo ninja!

• Limpieza automática del historial de Powershell tras la ejecución

• Ahora todas las dependencias se descargan del mismo repositorio

• Muchos errores y bugs corregidos

• Bypass de UAC & AMSI en sistemas de 64 bits

• Nuevo módulo disponible: Remote Desktop Forensics

• Nuevo módulo disponible: Desactivar logs del sistema (Invoke-Phant0m)

• Nuevo módulo disponible: Sticky Keys Hacking

• Nuevo módulo disponible: Local Port Forwarding

• Nuevo módulo disponible: Powershell Web Server

• Nuevo ataque disponible: Session Hijacking (sin contraseña)

**ATENCIÓN!** Este ataque es muy intrusivo y solo puede utilizarse localmente

*El resto de cambios se pueden consultar en el fichero CHANGELOG


# Uso
Esta aplicación puede usarse de forma local, remota o para pivotar entre equipos. 
Gracias a los módulos adicionales, es posible volcar hashes y contraseñas o incluso recuperar el histórico de conexiones RDP.

**Ejecución en una línea:**

powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

**La guía detallada de uso se encuentra en el siguiente enlace:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Capturas de pantalla
![autordpwn_es1](https://user-images.githubusercontent.com/34335312/49519365-1b862780-f8a1-11e8-9f18-744bf3860059.png)
![autordpwn_es2](https://user-images.githubusercontent.com/34335312/49519366-1b862780-f8a1-11e8-97f7-555845ef49f4.png)


# Licencia
Este proyecto está licenciando bajo la licencia GNU 3.0 - ver el fichero LICENSE para más detalles.


# Créditos y Agradecimientos
• **Mark Russinovich** por su herramienta PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• **HarmJ0y & Matt Graeber** por su script Get-System -> https://github.com/HarmJ0y/Misc-PowerShell

• **Stas'M Corp.** por su herramienta RDP Wrapper -> https://github.com/stascorp/rdpwrap

• **Kevin Robertson** por su script Invoke-TheHash -> https://github.com/Kevin-Robertson/Invoke-TheHash

• **Benjamin Delpy** por su herramienta Mimikatz -> https://github.com/gentilkiwi/mimikatz

• **Halil Dalabasmaz** por su script Invoke-Phant0m -> https://github.com/hlldz/Invoke-Phant0m


# Contacto
Este software no ofrece ningún tipo de garantía. Su uso es exclusivo para entornos educativos y/o auditorías de seguridad con el correspondiente consentimiento del cliente. No me hago responsable de su mal uso ni de los posibles daños causados por el mismo.

Para más información, puede contactar a través de info@darkbyte.net

-------------------------------------------------------------------------------------------------------------
# English description

**AutoRDPwn** is a script created in Powershell and designed to automate the **Shadow** attack on Microsoft Windows computers. This vulnerability allows a remote attacker to view his victim's desktop without his consent, and even control it on request. For its correct operation, it is necessary to comply with the requirements described in the user guide.


# Requirements
Powershell 5.0 or higher


# Changes
## Version 4.5
• New ninja style icon!

• Automatic cleaning of Powershell history after execution

• Now all dependencies are downloaded from the same repository

• Many errors and bugs fixed

• UAC & AMSI bypass in 64-bit systems

• New module available: Remote Desktop Forensics

• New module available: Disable system logs (Invoke-Phant0m)

• New module available: Sticky Keys Hacking

• New available module: Local Port Forwarding

• New available module: Powershell Web Server

• New available attack: Session Hijacking (passwordless)

**WARNING!** This attack is very intrusive and can only be used locally

*The rest of the changes can be consulted in the CHANGELOG file


# Use
This application can be used locally, remotely or to pivot between computers. Thanks to the additional modules, it is possible to dump hashes and passwords or even recover the history of RDP connections.


**One line execution:**

powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

**The detailed guide of use can be found at the following link:**

https://darkbyte.net/autordpwn-la-guia-definitiva

# Screenshots
![autordpwn_en1](https://user-images.githubusercontent.com/34335312/49519367-1b862780-f8a1-11e8-9465-ce649b94d4cd.png)
![autordpwn_en2](https://user-images.githubusercontent.com/34335312/49519364-1b862780-f8a1-11e8-8d80-e00e4c2eb931.png)


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
• **Mark Russinovich** for his tool PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• **HarmJ0y & Matt Graeber** for his script Get-System -> https://github.com/HarmJ0y/Misc-PowerShell

• **Stas'M Corp.** for its RDP tool Wrapper -> https://github.com/stascorp/rdpwrap

• **Kevin Robertson** for his script Invoke-TheHash -> https://github.com/Kevin-Robertson/Invoke-TheHash

• **Benjamin Delpy** for his tool Mimikatz -> https://github.com/gentilkiwi/mimikatz

• **Halil Dalabasmaz** for his script Invoke-Phant0m -> https://github.com/hlldz/Invoke-Phant0m


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can contact through info@darkbyte.net

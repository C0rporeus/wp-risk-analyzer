# 1. Análisis Estático (SAST) como Primera Línea de Defensa en Ecosistemas de Terceros

Date: 2026-02-28

## Status
Aceptado

## Contexto
En arquitecturas que dependen de ecosistemas altamente extensibles y gestionados por la comunidad (como WordPress o Node.js/npm), la inclusión de un plugin, tema o librería puede introducir fallos críticos de seguridad (RCE, SQLi, LFI). Aunque implementamos seguridad en tiempo de ejecución (contenedores inmutables, WAF, etc. en el proyecto `wp-enterprise-runtime`), confiar únicamente en capas operativas es un enfoque reactivo.

## Decisión
Desarrollamos e implementaremos el **WordPress Risk Analyzer (wp-risk-analyzer)**, una herramienta CLI basada en Rust, para ejecutar Análisis Estático de Seguridad del Código (SAST) en los plugins de terceros antes de que sean empacados en la imagen de Docker corporativa.

Hemos elegido **Rust** para esta herramienta por las siguientes razones:
1. **Rendimiento:** Permite escanear miles de archivos PHP en milisegundos utilizando concurrencia nativa, integrándose en el pipeline CI sin agregar tiempos muertos perceptibles.
2. **Distribución Independiente:** Genera un binario estático que no requiere la instalación de un runtime previo (como NodeJS o Python), facilitando su distribución a equipos DevSecOps.

## Consecuencias
- **Shift-Left Security:** La seguridad se mueve hacia las fases tempranas del ciclo de vida (CI). Si un plugin contiene uso directo de `$_GET` no sanitizado, el pipeline de Build fallará y evitará su despliegue.
- **Auditoría Continua:** Se calcula un `Risk Score`. Si un plugin supera un umbral de riesgo, requerirá la revisión de un ingeniero de seguridad antes de ser admitido.
- **Falsos Positivos:** El análisis basado en expresiones regulares (Regex) puede generar falsos positivos. Como mitigación futura, la herramienta podrá ser evolucionada a parseo AST (Abstract Syntax Tree) usando librerías como `tree-sitter`.
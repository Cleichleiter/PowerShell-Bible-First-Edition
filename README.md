PowerShell Bible



Ops-Focused Automation \& Troubleshooting Toolkit



PowerShell Bible is a practical, operations-first PowerShell reference built for real-world systems engineering and MSP environments. It consolidates reusable templates, hardened patterns, cheat sheets, and field-tested scripts used for day-to-day administration, troubleshooting, and automation.



This repository is not a beginner tutorial. The focus is clarity, safety, and reliability under pressure.



Purpose



PowerShell Bible exists to:



Reduce cognitive load during incidents



Standardize script structure and behavior



Capture repeatable solutions to common operational problems



Serve as a living reference for systems engineers



Scope



Covered domains include:



Active Directory administration



RDS / Terminal Services session management



Networking and DNS troubleshooting



Authentication and identity failure analysis



Scheduled tasks and automation patterns



Endpoint hygiene and remediation



Object-based reporting and logging standards



Repository Structure

PowerShell-Bible/

│

├── docs/         # Long-form guidance, standards, and patterns

├── cheatsheets/  # Fast lookup references and command summaries

├── templates/    # Script and function scaffolding

├── modules/      # Reusable PowerShell tooling

├── snippets/     # Task-focused operational scripts

├── examples/     # Sample outputs and reports

└── README.md



How to Use This Repository



This repository is organized around intent, not theory.



Snippets (Primary Entry Point)



The snippets/ directory contains ready-to-run, task-focused scripts designed for real operational use (RDS cleanup, network diagnostics, AD hygiene, firewall inspection, etc.).



Start here when:



You are troubleshooting an active issue



You need fast signal, not abstraction



You want scripts that work standalone or via RMM



Most users will spend the majority of their time in snippets/.



Docs



The docs/ directory explains why things are done a certain way, including:



Logging and error-handling standards



Remoting and execution patterns



Scheduled task design



Script safety and structure expectations



Read these when:



Writing new automation



Reviewing or extending scripts



Standardizing team practices



Cheat Sheets



The cheatsheets/ directory provides high-signal command references for common tasks (AD, RDS, filesystem, reporting).



Use these when:



You need recall under pressure



You want canonical examples



You are onboarding into the repo



Templates \& Modules



Use templates/ and modules/ as building blocks:



Templates for new scripts that follow repo standards



Modules for shared logic and reusable functions



Design Principles



Object output over formatted text



Explicit logging and error handling



Safe defaults with clear rollback paths



Readability over cleverness



Reusability over one-off solutions



Usage Expectations



This repository is intended for:



Local execution



RMM tooling



Incident response



Knowledge sharing



Script scaffolding for new automation



Review and adapt scripts for your environment before production use.



License



This project is licensed under the MIT License.


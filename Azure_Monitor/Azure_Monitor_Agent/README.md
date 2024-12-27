---
services: Azure Monitor Agent
platforms: Azure
author: scottmetzel
date: 12/06/2024
---
# Overview

This script provides a scaleable solution for installing the Azure Monitor Agent on Azure Virtual Machines, Virtual Machine Scale Sets, and Arc-enabled Servers in a specified scope.

# Prerequisites

- You must be assigned the *Azure Connected Machine Resource Administrator* role for the scope the script is run at.
- You must be connected to Azure. If your account have access to multiple Entra ID tenants and Azure subscriptions, make sure to log in with a specific tenant ID.


# Launching the script
# IdentityVault

IdentityVault is a prototype identity management system that allows users to control how their personal identity attributes are shared with external applications.

Instead of exposing a single static identity across multiple services, users can create contextual identity profiles and explicitly manage which applications may access their data.

The system demonstrates how privacy-by-design principles such as explicit consent, data minimisation, and user-controlled access can be implemented through a secure API architecture.

This project was developed as part of a Bachelor's thesis exploring context-sensitive identity management.


# Key Features

## Contextual Identity Profiles

Users can create multiple identity profiles within a single account. Each profile contains identity attributes that may be shared selectively with external applications.

Example attributes include:

- First name  
- Last name  
- Email address  
- Birth year  
- City  

Profiles allow users to separate identity contexts, for example professional and private usage.



## Consent Lifecycle Management

Access between an application and a profile is governed through an explicit consent lifecycle:

- **pending** – connection initiated but not yet approved  
- **granted** – access authorised by the user  
- **denied** – access rejected by the user  
- **revoked** – previously granted access withdrawn  

This lifecycle is enforced server-side to prevent client-side manipulation.


## Secure API Authentication

IdentityVault separates authentication and authorisation into two layers.

### User Authentication
Users authenticate using **JSON Web Tokens (JWT)**.

### Application Authentication
External applications authenticate using **application API keys**, stored as SHA-256 hashes.

### Consent-based Authorisation
Identity retrieval requires a valid **consent token** associated with a granted consent relationship.

Only when all three conditions are satisfied will identity data be returned.



## Attribute Filtering and Data Minimisation

Applications receive only the identity attributes they are explicitly permitted to access.

IdentityVault enforces this restriction at the API layer by filtering profile data before constructing the JSON response.

This prevents excessive disclosure of personal information.



## User-Controlled Data Rights

The web interface allows users to:

- create and manage identity profiles  
- connect applications  
- grant or deny access  
- revoke previously granted access  
- export stored personal data  
- permanently delete their account  



# System Architecture

IdentityVault is implemented using **Django** and **Django REST Framework (DRF)**.

The project is structured into four main Django applications:

- accounts: user authentication and account endpoints
- profiles: contextual identity profile management
- connections: consent relationships and API authentication
- vault_ui: web-based user interface


External applications interact with IdentityVault through RESTful API endpoints.

Example identity retrieval endpoint:

/api/applications/{application_id}/identity/


This endpoint verifies application authentication, consent status, and attribute permissions before returning identity data.



# Technology Stack

## Backend
- Python 3
- Django
- Django REST Framework

## Authentication
- JSON Web Tokens (SimpleJWT)

## Frontend
- Django Templates
- HTML
- CSS
- Bootstrap

## Database
- SQLite (development)



# Demonstration with LinkedInside

The repository includes a small demo application called LinkedInside that simulates an external partner service requesting identity data.

LinkedInside is a static HTML page and can be served locally.

Navigate to the LinkedInside folder and run:

python3 -m http.server 9000

Open:

http://127.0.0.1:9000




# Demo Workflow

1. Register or log in to IdentityVault
2. Create a contextual identity profile
3. Connect the LinkedInside application
4. Grant access to generate a consent token
5. Generate an application API key via the Django shell
6. Use the API key and consent token within LinkedInside to request identity data
7. Revoke access to demonstrate that the API request is blocked



# Security Considerations

IdentityVault incorporates several security mechanisms:

- API key hashing using SHA-256
- cryptographically generated consent tokens
- server-side enforcement of consent state transitions
- request throttling
- CSRF protection for web interface actions
- HTTPS support for secure communication

These controls implement a defence-in-depth approach to protecting identity data.




# Project Purpose

This project explores how identity management systems can move beyond traditional single-profile models toward context-sensitive identity disclosure controlled by explicit user consent.

IdentityVault demonstrates how such a system can be implemented using a modern web framework and secure API architecture.

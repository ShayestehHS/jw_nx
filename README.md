# JW-NX
___

### About package
This package provides an authentication mechanism for Django Rest Framework based on JSON Web Tokens in the browser-backed up Knox-powered tokens in the database.  
This package aims to take the better parts of both worlds, including 
- Expirable tokens: The tokens may be manually expired in the database, so a user can log out of all other logged-in places, or everywhere.   
 - Different tokens per login attempt (per user-agent): A user's session is tied to the specific machine and logging can be segregated per usage.  
  - JWT-base tokens: The token can have an embedded expiration time and further metadata for other applications.  
  - Only the tokens' hashes are stored in the database: So that even if the database gets dumped, an attacker cannot impersonate people through existing credentials.  
  - Access and refresh token: Like the rest-framework-simplejwt package, this package create refresh token and access token in login attempt and authentication is working with the access token.  
 - Other applications sharing the JWT private key can also decrypt the JWT.  
 - This package provides some endpoint for getting some data about the statuses of tokens.  
 
**Note**  : Token_key that provided by knox, is set in payload of access and refresh token.  
  
  
Installation  
----
  
For installing this package in your environment run these commands:

     pip install jw_nx
     pip install django-rest-knox

Quick start  
-----------  
  
 - Add "jw_nx and knox" to your INSTALLED_APPS setting like this:


    INSTALLED_APPS = [   
        ...  
        'knox',   
        'jw_nx',  
        ...   
    ]
 
 - Include the polls URLconf in your project urls.py like this::  
  
 path('jw_nx/', include('jw_nx.urls')),  
 - Run ``python manage.py makemigrations``.  
 - Run ``python manage.py migrate``.  
  
 - Add 'jw_nx.auth.JSONWebTokenKnoxAuthentication' to REST_FRAMEWORK like this::  


    REST_FRAMEWORK =[ 
       ... 
       'DEFAULT_AUTHENTICATION_CLASSES': 
           ('jw_nx.auth.JSONWebTokenKnoxAuthentication',),
       ...
    ]
   



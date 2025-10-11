# Static Files Directory

This directory contains static files for the Django application:

- CSS files
- JavaScript files  
- Images
- Icons
- Fonts

During development, Django will serve these files directly.
In production, these files should be collected using `python manage.py collectstatic`
and served by a web server like Nginx or using WhiteNoise.
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import os

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates an initial superuser/admin if none exists'

    def handle(self, *args, **options):
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@hospital.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin@12345')

        if not User.objects.filter(email=admin_email).exists():
            User.objects.create_superuser(
                email=admin_email,
                password=admin_password,
                full_name='Hospital Administrator',
                role='admin'
            )
            self.stdout.write(self.style.SUCCESS(f"Successfully created initial admin user: {admin_email}"))
        else:
            self.stdout.write(self.style.NOTICE(f"Admin user {admin_email} already exists."))

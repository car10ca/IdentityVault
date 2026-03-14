"""
Form definitions for profile creation and editing.

These forms provide server-side validation for profile data entered
through the user interface. Validation ensures that required fields
are present and that profile data remains consistent and secure.
"""
from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone

from .models import Profile


class ProfileCreateForm(forms.ModelForm):
    """
    Form used for both creating and editing profiles.

    Security guarantees:
    - Required fields enforced server-side
    - Email validated using Django's EmailField
    - Birth year validated against realistic bounds
    - Profile names unique per user
    """
    name = forms.CharField(
        required=True,
        error_messages={
            "required": "Profile name is required."
        },
        widget=forms.TextInput(attrs={
            "class": "form-control iv-input"
        })
    )

    first_name = forms.CharField(
        required=True,
        error_messages={
            "required": "First name is required."
        },
        widget=forms.TextInput(attrs={
            "class": "form-control iv-input"
        })
    )

    last_name = forms.CharField(
        required=True,
        error_messages={
            "required": "Last name is required."
        },
        widget=forms.TextInput(attrs={
            "class": "form-control iv-input"
        })
    )

    email = forms.EmailField(
        required=True,
        error_messages={
            "required": "Email is required.",
            "invalid": "Enter a valid email address."
        },
        widget=forms.EmailInput(attrs={
            "class": "form-control iv-input"
        })
    )

    birth_year = forms.IntegerField(
        required=True,
        error_messages={
            "required": "Birth year is required.",
            "invalid": "Enter a valid year."
        },
        widget=forms.NumberInput(attrs={
            "class": "form-control iv-input"
        })
    )

    city = forms.CharField(
        required=True,
        error_messages={
            "required": "City is required."
        },
        widget=forms.TextInput(attrs={
            "class": "form-control iv-input"
        })
    )

    class Meta:
        model = Profile
        fields = [
            "name",
            "first_name",
            "last_name",
            "email",
            "birth_year",
            "city",
        ]

    # =========================
    # Birth year validation
    # =========================

    def clean_birth_year(self):
        """
        Validate that the birth year is within a realistic range.
        Prevents impossible or future dates.
        """
        year = self.cleaned_data.get("birth_year")

        if year is None:
            return year

        current_year = timezone.now().year

        if year < 1900 or year > current_year:
            raise ValidationError(
                "Please enter a valid birth year."
            )

        return year

    # =========================
    # Name uniqueness validation
    # =========================

    def clean_name(self):
        """
        Ensure that profile names are unique for each user.

        A user may create multiple profiles, but profile names
        must not collide within the same account.
        """
        name = (self.cleaned_data.get("name") or "").strip()

        if not name:
            raise ValidationError("Profile name is required.")

        if self.instance.pk:
            user = self.instance.owner
        else:
            user = self.initial.get("owner")

        queryset = Profile.objects.filter(
            owner=user,
            name=name
        )

        if self.instance.pk:
            queryset = queryset.exclude(pk=self.instance.pk)

        if queryset.exists():
            raise ValidationError(
                "You already have a profile with this name."
            )

        return name

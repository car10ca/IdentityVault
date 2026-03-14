"""
vault_ui/views.py

Authentication + UI layer views.

Security principles applied:
- Built-in Django authentication framework
- CSRF protection enforced on POST
- Logout uses POST (not GET)
- Ownership enforcement via Profile.owner
- State transitions handled explicitly
- Account export uses authenticated POST
- Account deletion uses authenticated POST + logout
"""
import csv

from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib import messages
from django.db import IntegrityError
from django.db import transaction
from django.http import HttpResponseBadRequest, HttpResponse
from profiles.services.consent_service import (
    ConsentActionError,
    ConsentTransitionError,
    lock_and_apply_action,
)
from profiles.services.consent_service import connect_or_reset_to_pending
from django.db.models import Count, Q

from profiles.models import Application, Consent, Profile
from profiles.forms import ProfileCreateForm
from profiles.models_audit import ConsentAuditLog, ProfileAuditLog


from profiles.utils import get_user_profile_or_404


def landing_view(request):
    if request.user.is_authenticated:
        return redirect("vault_dashboard")
    return render(request, "vault_ui/landing.html")



# =========================
# Authentication Views
# =========================

def login_view(request):

    if request.method == "POST":

        form = AuthenticationForm(request, data=request.POST)

        if form.is_valid():

            login(request, form.get_user())

            return redirect("vault_dashboard")

    else:

        form = AuthenticationForm()

    return render(
        request,
        "vault_ui/auth/login.html",
        {"form": form},
    )


def register_view(request):

    if request.method == "POST":

        form = UserCreationForm(request.POST)

        if form.is_valid():

            user = form.save()

            authenticated_user = authenticate(
                request,
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password1"],
            )

            login(request, authenticated_user)

            messages.success(
                request,
                "Account successfully created."
            )

            return redirect("vault_dashboard")

    else:

        form = UserCreationForm()

    return render(
        request,
        "vault_ui/auth/register.html",
        {"form": form},
    )


@login_required
@require_POST
def logout_view(request):
    """
    Secure silent logout.

    - Requires POST (prevents CSRF logout attacks)
    - Destroys session
    - Redirects to public landing page
    - No flash message (avoids incorrect delayed feedback)
    """

    logout(request)

    # Redirect to public landing page (not login page)
    return redirect("vault_landing")


# =========================
# Dashboard
# =========================

@login_required
def dashboard_view(request):

    profiles = (
        Profile.objects
        .filter(owner=request.user)
        .annotate(
            connected_apps=Count(
                "consents",
                filter=Q(consents__status=Consent.Status.GRANTED),
            )
        )
        .order_by("created_at")
    )

    profile_rows = [
        {"id": p.id, "name": p.name, "connected_apps": p.connected_apps}
        for p in profiles
    ]

    return render(
        request,
        "vault_ui/dashboard/index.html",
        {"profiles": profile_rows},
    )

# =========================
# Profile Creation
# =========================

@login_required
def profile_create_view(request):
    """
    Create new Profile.

    Enforces:
    - Required fields
    - Ownership assigned server-side
    - Unique profile name per owner
    - Clear-all support (UX feedback)
    """

    # Clear all action (UX feedback)
    if request.method == "GET" and request.GET.get("clear") == "1":
        messages.info(request, "Form cleared.")
        return redirect("vault_profile_create")

    if request.method == "POST":

        # Pass owner through initial so clean_name() can validate correctly
        form = ProfileCreateForm(
            request.POST,
            initial={"owner": request.user},
        )

        if form.is_valid():

            profile = form.save(commit=False)
            profile.owner = request.user

            try:
                profile.save()

            except IntegrityError:
                form.add_error("name", "You already have a profile with this name.")

            else:
                messages.success(request, "Profile successfully created.")
                return redirect("vault_profile_detail", profile_id=profile.id)

    else:
        form = ProfileCreateForm()

    return render(
        request,
        "vault_ui/profile/create.html",
        {"form": form, "is_edit": False},
    )


# =========================
# Profile Edit
# =========================

@login_required
def profile_edit_view(request, profile_id):
    """
    Edit existing profile.

    Provides clear feedback for:
    - Changes saved
    - No changes made
    - Cancel action
    """

    profile = get_user_profile_or_404(request.user, profile_id)

    # Cancel action via GET
    if request.method == "GET" and request.GET.get("cancel") == "1":

        messages.info(
            request,
            "No changes were made."
        )

        return redirect(
            "vault_profile_detail",
            profile_id=profile.id
        )

    if request.method == "POST":

        form = ProfileCreateForm(
            request.POST,
            instance=profile
        )

        if form.is_valid():

            # CRITICAL: detect changes
            if form.has_changed():

                form.save()

                messages.success(
                    request,
                    "Profile successfully updated."
                )

            else:

                messages.info(
                    request,
                    "No changes were made."
                )

            return redirect(
                "vault_profile_detail",
                profile_id=profile.id
            )

    else:

        form = ProfileCreateForm(
            instance=profile
        )

    return render(
        request,
        "vault_ui/profile/create.html",
        {
            "form": form,
            "is_edit": True,
            "profile": profile,
        }
    )



# =========================
# Profile Delete
# =========================


@login_required
@require_POST
@transaction.atomic
def profile_delete_execute_view(request, profile_id):
    """
    Permanently delete profile and cascade-delete related consents.
    Writes audit log before deletion.
    """
    profile = get_user_profile_or_404(request.user, profile_id)

    consents_count = Consent.objects.filter(profile=profile).count()

    # Audit entry BEFORE deletion
    ProfileAuditLog.objects.create(
        actor=request.user,
        profile_id_snapshot=profile.id,
        profile_name_snapshot=profile.name,
        consents_deleted_count=consents_count,
        action=ProfileAuditLog.Action.DELETE,
    )

    profile_name = profile.name
    profile.delete()  # cascades to Consent

    messages.success(
        request,
        f"Profile '{profile_name}' was deleted successfully."
    )

    return redirect("vault_dashboard")



# =========================
# Account & Data Rights Page
# =========================

@login_required
def account_data_view(request):

    return render(
        request,
        "vault_ui/account_data.html"
    )


@login_required
@require_POST
def export_my_data_csv(request):

    user = request.user

    response = HttpResponse(
        content_type="text/csv; charset=utf-8"
    )

    response["Content-Disposition"] = (
        'attachment; filename="identityvault_export.csv"'
    )

    writer = csv.writer(response)

    writer.writerow(["SECTION", "ACCOUNT"])

    writer.writerow(["username", user.username])

    writer.writerow([
        "date_joined",
        user.date_joined.isoformat() if user.date_joined else ""
    ])

    writer.writerow([
        "last_login",
        user.last_login.isoformat() if user.last_login else ""
    ])

    writer.writerow([])

    writer.writerow(["SECTION", "PROFILES"])

    writer.writerow([
        "profile_id",
        "name",
        "created_at",
        "updated_at",
    ])

    profiles = Profile.objects.filter(
        owner=user
    ).order_by("id")

    for p in profiles:

        writer.writerow([
            p.id,
            p.name,
            p.created_at.isoformat() if p.created_at else "",
            "",
        ])

    writer.writerow([])

    writer.writerow(["SECTION", "CONSENTS"])

    writer.writerow([
        "consent_id",
        "profile_id",
        "application_name",
        "status",
        "granted_at",
        "revoked_at",
    ])

    consents = Consent.objects.filter(
        profile__owner=user
    ).select_related(
        "profile",
        "application"
    )

    for c in consents:

        writer.writerow([
            c.id,
            c.profile_id,
            c.application.name,
            c.status,
            c.granted_at.isoformat() if c.granted_at else "",
            c.revoked_at.isoformat() if c.revoked_at else "",
        ])

    return response


# =========================
# Account Deletion
# =========================

@login_required
@require_POST
def delete_my_account(request):

    user = request.user

    user.delete()

    logout(request)

    return redirect("vault_account_deleted")


def account_deleted_view(request):

    return render(
        request,
        "vault_ui/account_deleted.html"
    )


# =========================
# Profile Detail
# =========================

@login_required
def profile_detail_view(request, profile_id):

    profile = get_user_profile_or_404(request.user, profile_id)

    consents = Consent.objects.filter(
        profile=profile
    ).select_related(
        "application"
    )

    connected_app_ids = consents.values_list(
        "application_id",
        flat=True
    )

    available_apps = Application.objects.exclude(
        id__in=connected_app_ids
    )

    return render(
        request,
        "vault_ui/profile/detail.html",
        {
            "profile": profile,
            "consents": consents,
            "available_apps": available_apps,
        },
    )


# =========================
# Connect Application
# =========================

@login_required
@require_POST
def connect_application_view(request, profile_id):

    profile = get_object_or_404(
        Profile,
        id=profile_id,
        owner=request.user,
    )

    app_id = request.POST.get("application_id")

    application = get_object_or_404(
        Application,
        id=app_id,
    )

    consent, created = Consent.objects.get_or_create(
        profile=profile,
        application=application,
        defaults={"status": Consent.Status.PENDING},
    )

    if not created:
        # If previously denied or revoked, restart review cycle
        connect_or_reset_to_pending(consent)

    ConsentAuditLog.objects.create(
        actor=request.user,
        profile=profile,
        application=application,
        old_status="",
        new_status=str(consent.status),
        action=ConsentAuditLog.Action.CONNECT,
    )

    return redirect(
        "vault_consent_detail",
        profile_id=profile.id,
        app_id=application.id,
    )



# =========================
# Consent Detail
# =========================

@login_required
def consent_detail_view(request, profile_id, app_id):

    profile = get_user_profile_or_404(request.user, profile_id)

    consent = get_object_or_404(
        Consent,
        profile=profile,
        application_id=app_id
    )

    application = consent.application

    # Pop one-time token for display (if a grant just happened)
    issued_token = request.session.pop(
        f"consent_token_once:{profile.id}:{app_id}",
        None
    )

    context = {
        "status": consent.status,
        "feedback": request.GET.get("feedback"),
        "issued_consent_token": issued_token,

        "profile_name": profile.name,
        "application_name": application.name,
        "data_list": "First name, Last name, Email, Birth year, City",

        "profile_id": profile.id,
        "application_id": application.id,
    }

    return render(
        request,
        "vault_ui/consent/detail.html",
        context,
    )


# =========================
# Consent State Transitions
# =========================

@login_required
@require_POST
def consent_action_view(request):

    action = request.POST.get("action")
    profile_id = request.POST.get("profile_id")
    application_id = request.POST.get("application_id")

    if not action or not profile_id or not application_id:
        return HttpResponseBadRequest("Missing required fields")

    profile = get_user_profile_or_404(request.user, profile_id)

    # Use a queryset so we can lock the row atomically in the service.
    consent_qs = Consent.objects.filter(
        profile=profile,
        application_id=application_id
    )

    try:
        consent, feedback, raw_token = lock_and_apply_action(
            consent_qs,
            action,
            actor=request.user,
        )

    except ConsentActionError:
        return HttpResponseBadRequest("Invalid action")

    except ConsentTransitionError:
        return HttpResponse("Illegal state transition", status=409)

    # Store raw token ONE TIME in session for UI display after granting.
    # Not in URL (avoids history/log leakage).
    if action == "grant" and raw_token:
        request.session[f"consent_token_once:{profile.id}:{application_id}"] = raw_token
    url = reverse(
        "vault_consent_detail",
        kwargs={
            "profile_id": profile.id,
            "app_id": int(application_id),
        },
    )

    if feedback:
        url += f"?feedback={feedback}"

    return redirect(url)

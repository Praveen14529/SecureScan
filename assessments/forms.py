from django import forms
from .models import Asset, Assessment


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ["name", "asset_type", "owner", "criticality", "description"]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control"}),
            "asset_type": forms.Select(attrs={"class": "form-select"}),
            "owner": forms.TextInput(attrs={"class": "form-control"}),
            "criticality": forms.Select(attrs={"class": "form-select"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
        }


class AssessmentCreateForm(forms.ModelForm):
    class Meta:
        model = Assessment
        fields = ["title", "assessor", "notes"]
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control"}),
            "assessor": forms.TextInput(attrs={"class": "form-control"}),
            "notes": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
        }

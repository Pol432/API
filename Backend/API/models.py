from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.utils.translation import gettext_lazy as _


class University(models.Model):
    """
    University details model
    """
    name = models.CharField(
        _('University Name'),
        max_length=100,
        unique=True
    )
    acronym = models.CharField(
        _('University Acronym'),
        max_length=100,
        unique=True
    )

    class Meta:
        verbose_name = _('University')
        verbose_name_plural = _('Universities')

    def __str__(self):
        return self.name


class Campus(models.Model):
    """
    Campus model to represent specific locations within a university
    """
    name = models.CharField(
        _('Campus Name'),
        max_length=100
    )
    university = models.ForeignKey(
        University,
        on_delete=models.CASCADE,
        related_name='campus_set',
        verbose_name=_('University')
    )
    address = models.TextField(
        _('Campus Address'),
        blank=True
    )

    class Meta:
        verbose_name = _('Campus')
        verbose_name_plural = _('Campuses')
        unique_together = ('name', 'university')

    def __str__(self):
        return f"{self.name} - {self.university.name}"


class Account(AbstractUser):
    """
    Extended user model to include university-specific information
    """
    university = models.ForeignKey(
        University,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users',
        verbose_name=_('University')
    )

    integrity_points = models.PositiveIntegerField(
        _('Integrity Points'),
        default=0,
        help_text=_('Points earned through ethical actions and reports')
    )

    class Meta:
        verbose_name = _('User Account')
        verbose_name_plural = _('User Accounts')

    def __str__(self):
        return f"{self.username} - {self.university.name if self.university else 'No University'}"


class ReportCategory(models.Model):
    """
    Categories for different types of reports
    """
    name = models.CharField(
        _('Category Name'),
        max_length=50,
        unique=True
    )
    description = models.TextField(
        _('Category Description'),
        blank=True
    )

    class Meta:
        verbose_name = _('Report Category')
        verbose_name_plural = _('Report Categories')

    def __str__(self):
        return self.name


class Report(models.Model):
    """
    Model to track and manage reports of ethical issues
    """
    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('in_progress', _('In Progress')),
        ('resolved', _('Resolved')),
        ('closed', _('Closed'))
    ]

    university = models.ForeignKey(
        University,
        on_delete=models.CASCADE,
        related_name='reports',
        verbose_name=_('University')
    )
    campus = models.ForeignKey(
        Campus,
        on_delete=models.CASCADE,
        related_name='reports',
        verbose_name=_('Campus')
    )
    title = models.CharField(
        _('Report Title'),
        max_length=100
    )
    description = models.TextField(
        _('Description'),
        max_length=1000
    )
    category = models.ForeignKey(
        ReportCategory,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reports',
        verbose_name=_('Report Category')
    )
    image = models.ImageField(
        _('Evidence Image'),
        upload_to='report_images/',
        validators=[FileExtensionValidator(['png', 'jpg', 'jpeg'])],
        blank=True,
        null=True
    )

    university = models.CharField(
        _('University'),
        max_length=100
    )
    specific_location = models.CharField(
        _('Specific Location'),
        max_length=100,
        blank=True
    )
    status = models.CharField(
        _('Report Status'),
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )

    posted_by = models.ForeignKey(
        Account,
        on_delete=models.CASCADE,
        related_name='reports',
        verbose_name=_('Reported By')
    )

    created_at = models.DateTimeField(
        _('Created At'),
        auto_now_add=True
    )
    updated_at = models.DateTimeField(
        _('Last Updated'),
        auto_now=True
    )
    occured_at = models.DateTimeField(
        _('Event occured at'),
        auto_now=True
    )

    class Meta:
        verbose_name = _('Ethical Report')
        verbose_name_plural = _('Ethical Reports')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} - {self.status}"


class Challenge(models.Model):
    """
    Ethical challenges for user engagement and learning
    """
    DIFFICULTY_LEVELS = [
        ('beginner', _('Beginner')),
        ('intermediate', _('Intermediate')),
        ('advanced', _('Advanced'))
    ]

    title = models.CharField(
        _('Challenge Title'),
        max_length=100
    )
    description = models.TextField(
        _('Challenge Description')
    )
    difficulty = models.CharField(
        _('Difficulty Level'),
        max_length=20,
        choices=DIFFICULTY_LEVELS,
        default='beginner'
    )
    points_reward = models.PositiveIntegerField(
        _('Integrity Points Reward'),
        default=10
    )
    category = models.ForeignKey(
        ReportCategory,
        on_delete=models.SET_NULL,
        null=True,
        related_name='challenges',
        verbose_name=_('Related Category')
    )

    created_at = models.DateTimeField(
        _('Created At'),
        auto_now_add=True
    )

    class Meta:
        verbose_name = _('Ethical Challenge')
        verbose_name_plural = _('Ethical Challenges')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.difficulty})"

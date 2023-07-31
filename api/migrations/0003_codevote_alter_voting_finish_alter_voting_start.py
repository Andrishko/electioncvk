# Generated by Django 4.2 on 2023-05-22 11:58

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_alter_voting_finish_alter_voting_start'),
    ]

    operations = [
        migrations.CreateModel(
            name='codeVote',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=1000)),
                ('vote', models.CharField(max_length=1000)),
            ],
        ),
        migrations.AlterField(
            model_name='voting',
            name='finish',
            field=models.DateTimeField(default=datetime.datetime(2023, 5, 22, 14, 58, 21, 479033)),
        ),
        migrations.AlterField(
            model_name='voting',
            name='start',
            field=models.DateTimeField(default=datetime.datetime(2023, 5, 22, 14, 58, 21, 479033)),
        ),
    ]

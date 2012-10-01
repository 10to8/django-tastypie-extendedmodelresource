from django.contrib.auth.models import User

from tastypie import fields

from models import Entry, EntryInfo

from extendedmodelresource import ExtendedModelResource


from tastypie.resources import ModelResource, ALL, ALL_WITH_RELATIONS


class UserResource(ExtendedModelResource):
    class Meta:
        queryset = User.objects.all()
        resource_name = 'user'
        filtering = {
            'id': ALL,

        }

    class Nested:
        entries = fields.ToManyField('api.resources.EntryResource', 'entries')


class EntryResource(ExtendedModelResource):
    user = fields.ForeignKey(UserResource, 'user')

    class Meta:
        queryset = Entry.objects.all()
        resource_name = 'entry'
        filtering = {
            'user': ALL_WITH_RELATIONS,
            'title': ALL,
            'id': ALL,
        }

    class Nested:
        entryinfo = fields.OneToManyField('api.resources.EntryInfoResource',
                                         'entryinfo')


class EntryInfoResource(ExtendedModelResource):
    class Meta:
        queryset = EntryInfo.objects.all()
        resource_name = 'EntryInfo'


class UserByNameResource(ExtendedModelResource):
    class Meta:
        queryset = User.objects.all()
        resource_name = 'userbyname'
        detail_uri_name = 'username'


    def get_url_id_attribute_regex(self):
        # The id attribute respects this regex.
        return r'[aA-zZ][\w-]*'

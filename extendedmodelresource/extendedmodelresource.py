import re
import pytz
import logging
import dateutil.parser

from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse, HttpResponseNotFound, Http404
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.core.urlresolvers import get_script_prefix, resolve, Resolver404, NoReverseMatch
from django.conf.urls.defaults import patterns, url
from django.db.models import Q
from tastypie import fields, http
from tastypie.bundle import Bundle
from tastypie.exceptions import NotFound, ImmediateHttpResponse, BadRequest
from tastypie.utils.mime import determine_format, build_content_type
from tastypie.exceptions import ApiFieldError
from tastypie.utils import trailing_slash, dict_strip_unicode_keys
from tastypie.resources import (ResourceOptions,
                                ModelDeclarativeMetaclass,
                                ModelResource,
                                convert_post_to_put)


from tastypie.serializers import Serializer


class TimeZoneSerializer(Serializer):

    def format_datetime(self, data):
        """
        A hook to control how datetimes are formatted.

        Can be overridden at the ``Serializer`` level (``datetime_formatting``)
        or globally (via ``settings.TASTYPIE_DATETIME_FORMATTING``).

        Default is ``iso-8601``, which looks like "2010-12-16T03:02:14".
        """
        return data.isoformat()

def nested_detail_uri_matcher(uri):
    expression = "/(?P<url>[\w/]+)/(?P<resource_name>\w+)/(?P<pk>\d+)/(?P<child_resource_name>\w+)/(?P<child_pk>\d+)/?$"
    result = re.match(expression, uri)
    if result is None:
        return None
    return result.groupdict()


def convert_to_utc(dt):
    """
    Convert to UTC.
    """
    if not dt.tzinfo:
        return dt.replace(tzinfo=pytz.UTC)
    return dt.astimezone(pytz.UTC)


class FullToOneField(fields.ToOneField):
    def __init__(self, *args, **kwargs):
        self.full_requestable = kwargs.pop('full_requestable', True)

        super(FullToOneField, self).__init__(*args, **kwargs)


    def dehydrate(self, bundle):
        """
        10to8 changes: We pass on the full_depth value to the fk_bundle.
        """
        foreign_obj = None

        if isinstance(self.attribute, basestring):
            attrs = self.attribute.split('__')
            foreign_obj = bundle.obj

            for attr in attrs:
                previous_obj = foreign_obj
                try:
                    foreign_obj = getattr(foreign_obj, attr, None)
                except ObjectDoesNotExist:
                    foreign_obj = None
        elif callable(self.attribute):
            foreign_obj = self.attribute(bundle)

        if not foreign_obj:
            if not self.null:
                raise ApiFieldError("The model '%r' has an empty attribute '%s' and doesn't allow a null value." % (previous_obj, attr))

            return None

        full_depth = getattr(bundle, 'full_depth', 0)
        self.fk_resource = self.get_related_resource(foreign_obj)
        fk_bundle = Bundle(obj=foreign_obj, request=bundle.request)
        fk_bundle.full_depth = full_depth

        return self.dehydrate_related(fk_bundle, self.fk_resource)

    def dehydrate_related(self, bundle, related_resource):
        """
        10to8 changes: We pass on the full_depth argument to our child - reduced by one.
        """
        """
        Based on the ``full_resource``, returns either the endpoint or the data
        from ``full_dehydrate`` for the related resource.
        """
        full_depth = getattr(bundle, 'full_depth', 0)
        if (not (full_depth > 0 and self.full_requestable) and
            not self.full):

            return related_resource.get_resource_uri(bundle)
        else:
            # ZOMG extra data and big payloads.
            new_bundle = related_resource.build_bundle(obj=related_resource.instance, request=bundle.request)

            if self.full_requestable:
                # Don't pass down 'full' if it's not allowed on this resource.
                # decremet full_depth
                new_bundle.full_depth = max(full_depth - 1, 0)
            else:
                new_bundle.full_depth = 0
            return related_resource.full_dehydrate(new_bundle)


class FullToManyField(fields.ToManyField):
    """
    Like tastypies's ToManyField but makes the resource_uri correct for nested resources, and we understand `full_depth`.
    """

    def __init__(self, *args, **kwargs):
        self.full_requestable = kwargs.pop('full_requestable', True)
        self.delete_on_unlink = kwargs.pop('delete_on_unlink', False)
        super(FullToManyField, self).__init__(*args, **kwargs)

    def dehydrate(self, bundle, nested_uri=False):
        """
        10to8 changes:
            We pass on the full_depth to the m2m bundle.
        """

        if not bundle.obj or not bundle.obj.pk:
            if not self.null:
                raise ApiFieldError("The model '%r' does not have a primary key and can not be used in a ToMany context." % bundle.obj)

            return []

        the_m2ms = None
        previous_obj = bundle.obj
        attr = self.attribute

        if isinstance(self.attribute, basestring):
            attrs = self.attribute.split('__')
            the_m2ms = bundle.obj

            for attr in attrs:
                previous_obj = the_m2ms
                try:
                    the_m2ms = getattr(the_m2ms, attr, None)
                except ObjectDoesNotExist:
                    the_m2ms = None

                if not the_m2ms:
                    break

        elif callable(self.attribute):
            the_m2ms = self.attribute(bundle)

        if not the_m2ms:
            if not self.null:
                raise ApiFieldError("The model '%r' has an empty attribute '%s' and doesn't allow a null value." % (previous_obj, attr))

            return []

        self.m2m_resources = []
        m2m_dehydrated = []

        # TODO: Also model-specific and leaky. Relies on there being a
        #       ``Manager`` there.
        full_depth = getattr(bundle, 'full_depth', 0)

        for m2m in the_m2ms.all():
            m2m_resource = self.get_related_resource(m2m)
            m2m_bundle = Bundle(obj=m2m, request=bundle.request)
            m2m_bundle.full_depth = max(full_depth, 0)
            # Nested URI additions
            if nested_uri:
                m2m_bundle.parent_object = bundle.obj
                m2m_bundle.parent_resource = self._resource
                m2m_bundle.nested_name = self.instance_name # For building nested URI
            # end nested URI additions
            self.m2m_resources.append(m2m_resource)
            m2m_dehydrated.append(self.dehydrate_related(m2m_bundle, m2m_resource))

        return m2m_dehydrated

    def dehydrate_related(self, bundle, related_resource, nested_uri=False):
        """
        Based on the ``full_resource``, returns either the endpoint or the data
        from ``full_dehydrate`` for the related resource.

        10to8 changes:
            - We pass on the full_depth argument to our children - reduced by one.
        """
        full_depth = getattr(bundle, 'full_depth', 0)

        if (not (full_depth > 0 and self.full_requestable) and
            not self.full):
            # Be a good netizen.
            return related_resource.get_resource_uri(bundle)
        else:
            # ZOMG extra data and big payloads.
            #Why build a new bundle here?

            new_bundle = related_resource.build_bundle(obj=related_resource.instance, request=bundle.request)
            if nested_uri:
                new_bundle.parent_object=getattr(bundle, 'parent_object', None)
                new_bundle.nested_name = self.instance_name
                new_bundle.parent_resource = self._resource

            if self.full_requestable:
                # Don't pass down 'full' if it's not allowed on this resource.
                # decremet full_depth
                new_bundle.full_depth = max(full_depth - 1, 0)
            return related_resource.full_dehydrate(new_bundle)

class NestedToManyField(FullToManyField):
    """
    Like tastypies's ToManyField but makes the resource_uri correct for nested resources, and we understand `full_depth`.
    """

    def __init__(self, *args, **kwargs):
        self.nested_resource_name = kwargs.pop('nested_resource_name', None)
        super(NestedToManyField, self).__init__(*args, **kwargs)

    def dehydrate(self, bundle):
        """
        10to8 changes:
            We pass on the full_depth to the m2m bundle.
        """

        return super(NestedToManyField, self).dehydrate(bundle, nested_uri=True)

    def dehydrate_related(self, bundle, related_resource):
        """
        Based on the ``full_resource``, returns either the endpoint or the data
        from ``full_dehydrate`` for the related resource.

        10to8 changes:
            - We pass on the full_depth argument to our children - reduced by one.
        """
        return super(NestedToManyField, self).dehydrate_related(bundle, related_resource, nested_uri=True)

class ExtendedDeclarativeMetaclass(ModelDeclarativeMetaclass):
    """
    WARNING, WARNING, you MUST create ``nested_generic_fields`` in the parents Meta if you use generic relationships.
    Also if you don't use the default values for the three generic fields, you MUST set them.

    The default values are in `:py:func:get_generic_fields`.

    If you fail to do this YOU WILL RETURN ALL CHILD OBJECTS!

    This is clearly a TODO: to secure.
    ::
        nested_generic_fields = {
                                'numbers': True,
                                'emails : {
                                    'manager': 'my_manager',
                                    'object_id': 'blah_bject_id',
                                    'content_type': 'bloo_content_type'
                                }
                            },

    TODO: Fix this comment. It doesn't match the code. Where is
    AnyIdAttributeResourceOptions??
    """

    def __new__(mcs, name, bases, attrs):
        new_class = super(ExtendedDeclarativeMetaclass, mcs).__new__(mcs, name,
                                                                     bases, attrs)

        opts = getattr(new_class, 'Meta', None)
        new_class._meta = ResourceOptions(opts)

        # Will map nested fields names to the actual fields
        nested_fields = {}

        nested_class = getattr(new_class, 'Nested', None)
        if nested_class is not None:
            for field_name in dir(nested_class):
                if not field_name.startswith('_'):  # No internals
                    field_object = getattr(nested_class, field_name)

                    nested_fields[field_name] = field_object
                    if hasattr(field_object, 'contribute_to_class'):
                        field_object.contribute_to_class(new_class,
                                                         field_name)

        new_class._nested = nested_fields

        return new_class


class ExtendedModelResource(ModelResource):

    __metaclass__ = ExtendedDeclarativeMetaclass


    def _handle_500(self, request, exception):
        """

        :param request:
        :param exception:
        :return:
        """
        import traceback
        import sys
        the_trace = '\n'.join(traceback.format_exception(*(sys.exc_info())))
        response_class = http.HttpResponse
        response_code = 500

        NOT_FOUND_EXCEPTIONS = (NotFound, ObjectDoesNotExist, Http404)

        if isinstance(exception, NOT_FOUND_EXCEPTIONS):
            response_class = HttpResponseNotFound
            response_code = 404

        if settings.DEBUG or getattr(settings, 'TASTYPIE_FULL_DEBUG', False):
            data = {
                "error_message": unicode(exception),
                "traceback": the_trace,
            }
            desired_format = self.determine_format(request)
            serialized = self.serialize(request, data, desired_format)
            return response_class(content=serialized, content_type=build_content_type(desired_format))

        if not response_code == 404:

            # import traceback
            #
            # traceback.print_stack()
            # print traceback.format_exc()
            # raise exception

            log = logging.getLogger('django.request.tastypie')
            log.error('Internal Server Error: %s' % request.path, exc_info=sys.exc_info(), extra={'status_code': response_code, 'request':request})

            try:
                log2 = logging.getLogger('sentry')
                log2.error('Internal Server Error: %s' % request.path, exc_info=True, extra={'status_code': response_code, 'request':request})
            except:
                raise

        # check our exception class for help dealing with its errors..
        response_code = getattr(exception, "_api_error_code", response_code)
        raise_message = getattr(exception, "_api_raise_message", False)
        std_error_code = getattr(exception, "_api_std_error_code", "")
        default_error = getattr(exception, "_api_default_error", "There was a problem, please try again.")

        if raise_message:
            error = {'error': std_error_code, 'description': exception.message}
        else:
            error = {'error': std_error_code, 'description': default_error}

        data = {
            'error': 1,
            'errors': [error],
        }

        desired_format = self.determine_format(request)
        serialized = self.serialize(request, data, desired_format)
        return response_class(content=serialized, content_type=build_content_type(desired_format), status=response_code)

    def remove_api_resource_names(self, url_dict):
        """
        Override this function, we are going to use some data for Nesteds.
        """
        return url_dict.copy()

    def get_nested_uri_name_regex(self):

        return self.get_detail_uri_name_regex()

    def get_detail_uri_name_regex(self):
        """
        Return the regular expression to which the id attribute used in
        resource URLs should match.

        By default we admit any alphanumeric value and "-", but you may
        override this function and provide your own.
        """
        return r'\d*'

    def lookup_kwargs_with_identifiers(self, bundle, kwargs):
        """
        Kwargs here represent uri identifiers Ex: /repos/<user_id>/<repo_name>/
        We need to turn those identifiers into Python objects for generating
        lookup parameters that can find them in the DB

        Simplify, we only support lookups using the detail_uri_name, which defaults to `pk`
        """
        detail_uri = kwargs.get(self._meta.detail_uri_name, None)

        if detail_uri is not None:
            return {self._meta.detail_uri_name: detail_uri}
        else:
            lookup_kwargs = {}

        for identifier in kwargs:
            if identifier == 'resource_uri':
                result = nested_detail_uri_matcher(kwargs[identifier])

                if result is not None:
                    if not result['resource_name'] == self._meta.resource_name: # make sure we're not the parent.
                        lookup_kwargs[self._meta.detail_uri_name] = result['child_pk']

        return lookup_kwargs

    def real_remove_api_resource_names(self, url_dict):
        """
        Given a dictionary of regex matches from a URLconf, removes
        ``api_name`` and/or ``resource_name`` if found.

        This is useful for converting URLconf matches into something suitable
        for data lookup. For example::

            Model.objects.filter(**self.remove_api_resource_names(matches))
        """
        kwargs_subset = url_dict.copy()

        exclude_keys = ['generic_fields',
                        'api_name',
                        'resource_name',
                        'related_manager',
                        'child_object',
                        'parent_resource',
                        'nested_name',
                        'nested_field_name',
                        'parent_object']

        #related_keys_search = []

        #if 'related_manager' in kwargs_subset.keys():
        #    manager = kwargs_subset['related_manager']
        #    if hasattr(manager, "content_type_field_name"):
        #        exclude_keys.append(manager.content_type_field_name)
        #        related_keys_search.append(manager.content_type_field_name)
        #
        #    if hasattr(manager, "object_id_field_name"):
        #        exclude_keys.append(manager.object_id_field_name)
        #        related_keys_search.append(manager.object_id_field_name)


        for key in exclude_keys:
            try:
                del(kwargs_subset[key])
            except KeyError:
                pass

        #for key in related_keys_search:
        #    for key2 in kwargs_subset.keys():
        #        if key2.startswith(key + '__'):
        #            del(kwargs_subset[key2])


        return kwargs_subset


    def detail_nested_uri_kwargs(self, bundle_or_obj):

        kwargs = { }

        if bundle_or_obj is not None:
            try:
                if isinstance(bundle_or_obj, Bundle):
                    if getattr(bundle_or_obj, 'obj', None) is not None:
                        kwargs[self._meta.nested_detail_uri_name] = getattr(bundle_or_obj.obj, 'pk')
                else:
                    kwargs[self._meta.nested_detail_uri_name] = getattr(bundle_or_obj, 'pk')
            except AttributeError:
                raise ImmediateHttpResponse("Missing 'nested_detail_uri_name' on resource %s meta" % (self._meta.resource_name))

            if hasattr(bundle_or_obj, 'parent_object') and hasattr(bundle_or_obj, 'parent_resource'):
                kwargs[bundle_or_obj.parent_resource._meta.detail_uri_name] = getattr(bundle_or_obj.parent_object, bundle_or_obj.parent_resource._meta.detail_uri_name)

            if getattr(bundle_or_obj, 'nested_name', None) is not None:
                kwargs['nested_name'] = getattr(bundle_or_obj, 'nested_name', None)

        return kwargs


    def list_nested_uri_kwargs(self, bundle_or_obj):

        kwargs = { }

        if bundle_or_obj is not None:

            if hasattr(bundle_or_obj, 'parent_object') and hasattr(bundle_or_obj, 'parent_resource'):
                kwargs[bundle_or_obj.parent_resource._meta.detail_uri_name] = getattr(bundle_or_obj.parent_object, bundle_or_obj.parent_resource._meta.detail_uri_name)

            if getattr(bundle_or_obj, 'nested_name', None) is not None:
                kwargs['nested_name'] = getattr(bundle_or_obj, 'nested_name', None)

        return kwargs


    def resource_uri_kwargs(self, bundle_or_obj=None, url_name=''):
        """
        Builds a dictionary of kwargs to help generate URIs.

        Automatically provides the ``Resource.Meta.resource_name`` (and
        optionally the ``Resource.Meta.api_name`` if populated by an ``Api``
        object).

        If the ``bundle_or_obj`` argument is provided, it calls
        ``Resource.detail_uri_kwargs`` for additional bits to create
        """
        kwargs = {}
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name

        if hasattr(bundle_or_obj, 'parent_resource'):
            kwargs['resource_name'] = bundle_or_obj.parent_resource._meta.resource_name
            if url_name == 'api_dispatch_nested_detail':
                kwargs.update(self.detail_nested_uri_kwargs(bundle_or_obj))
            elif url_name == 'api_dispatch_nested_list':
                kwargs.update(self.list_nested_uri_kwargs(bundle_or_obj))
        else:
            kwargs['resource_name'] = self._meta.resource_name
            if url_name == 'api_dispatch_detail':
                kwargs.update(self.detail_uri_kwargs(bundle_or_obj))

        return kwargs


    def get_resource_uri(self, bundle_or_obj=None, url_name='api_dispatch_list'):

        if hasattr(bundle_or_obj, 'parent_object'):
            if bundle_or_obj is not None and getattr(bundle_or_obj, 'obj', None) is not None:
                url_name = 'api_dispatch_nested_detail'
            else:
                url_name = 'api_dispatch_nested_list'
        else:
            if bundle_or_obj is not None and getattr(bundle_or_obj, 'obj', None) is not None:
                url_name = 'api_dispatch_detail'
        try:
            kwargs = self.resource_uri_kwargs(bundle_or_obj, url_name=url_name)
            url = self._build_reverse_url(url_name, kwargs=kwargs)
            return url
        except NoReverseMatch:
            print 'Reverse url fail while building resource uri. url: %s, args: %s' % (url_name, kwargs)
            return u''

    def base_urls(self):
        """
        Same as the original ``base_urls`` but supports using the custom
        regex for the ``detail_uri_name`` attribute of the objects.
        """
        # Due to the way Django parses URLs, ``get_multiple``
        # won't work without a trailing slash.
        return [
            url(r"^(?P<resource_name>%s)%s$" %
                    (self._meta.resource_name, trailing_slash()),
                    self.wrap_view('dispatch_list'),
                    name="api_dispatch_list"),
            url(r"^(?P<resource_name>%s)/schema%s$" %
                    (self._meta.resource_name, trailing_slash()),
                    self.wrap_view('get_schema'),
                    name="api_get_schema"),
            url(r"^(?P<resource_name>%s)/set/(?P<%s_list>(%s;?)*)/$" %
                    (self._meta.resource_name,
                     self._meta.detail_uri_name,
                     self.get_detail_uri_name_regex()),
                    self.wrap_view('get_multiple'),
                    name="api_get_multiple"),
            url(r"^(?P<resource_name>%s)/(?P<%s>%s)%s$" %
                    (self._meta.resource_name,
                     self._meta.detail_uri_name,
                     self.get_detail_uri_name_regex(),
                     trailing_slash()),
                     self.wrap_view('dispatch_detail'),
                     name="api_dispatch_detail"),
        ]

    def nested_urls(self):
        """
        Return the list of all urls nested under the detail view of a resource.

        Each resource listed as Nested will generate one url.
        """
        def get_nested_url_detail(nested_name, field=None):

            if field is not None:
                nested_uri_name_regex = field.to_class().get_nested_uri_name_regex()
            else:
                nested_uri_name_regex = self.get_nested_uri_name_regex()

            return url(r"^(?P<resource_name>%s)/(?P<%s>%s)/"
                        r"(?P<nested_name>%s)/(?P<%s>%s)%s$" %
                       (self._meta.resource_name,
                        self._meta.detail_uri_name,
                        self.get_detail_uri_name_regex(),
                        nested_name,
                        'nested_pk',
                        nested_uri_name_regex,
                        trailing_slash()),
                       self.wrap_view('dispatch_nested_detail'),
                       name='api_dispatch_nested_detail')

        def get_nested_url_list(nested_name):
            return url(r"^(?P<resource_name>%s)/(?P<%s>%s)/"
                        r"(?P<nested_name>%s)%s$" %
                       (self._meta.resource_name,
                        self._meta.detail_uri_name,
                        self.get_detail_uri_name_regex(),
                        nested_name,
                        trailing_slash()),
                       self.wrap_view('dispatch_nested'),
                       name='api_dispatch_nested_list')

        urls = [get_nested_url_list(nested_name) for nested_name in self._nested.keys()]
        [urls.append(get_nested_url_detail(nested_name, self._nested[nested_name])) for nested_name in self._nested.keys()]
        return urls


    def detail_actions(self):
        """
        Return urls of custom actions to be performed on the detail view of a
        resource. These urls will be appended to the url of the detail view.
        This allows a finer control by providing a custom view for each of
        these actions in the resource.

        A resource should override this method and provide its own list of
        detail actions urls, if needed.

        For example:

        return [
            url(r"^show_schema/$", self.wrap_view('get_schema'),
                name="api_get_schema")
        ]

        will add show schema capabilities to a detail resource URI (ie.
        /api/user/3/show_schema/ will work just like /api/user/schema/).
        """
        return []

    @property
    def urls(self):
        """
        The endpoints this ``Resource`` responds to.

        Same as the original ``urls`` attribute but supports nested urls as
        well as detail actions urls.
        """
        urls = self.prepend_urls() + self.base_urls() + self.nested_urls()
        return patterns('', *urls)

    def is_authorized_over_parent(self, request, parent_object):
        """
        Allows the ``Authorization`` class to check if a request to a nested
        resource has permissions over the parent.

        Will call the ``is_authorized_parent`` function of the
        ``Authorization`` class.
        """

        if hasattr(self._meta.authorization, 'is_authorized_parent'):
            return self._meta.authorization.is_authorized_parent(request,
                        parent_object)
        else:
            raise NotImplementedError("'is_authorized_parent' could not be found on the Resources Authorization class. Please implement this function.")

        return True

    def parent_obj_get(self, request=None, **kwargs):
        """
        Same as the original ``obj_get`` but called when a nested resource
        wants to get its parent.

        Will check authorization to see if the request is allowed to act on
        the parent resource.
        """
        kwargs = self.real_remove_api_resource_names(kwargs)
        parent_object = self.get_object_list(request).get(**kwargs)

        if not self.is_authorized_over_parent(request, parent_object):
            stringified_kwargs = ', '.join(["%s=%s" % (k, v)
                                            for k, v in kwargs.items()])
            raise ImmediateHttpResponse(response=http.HttpUnauthorized("Authorisation failed for "
                    "instance of '%s' which matched '%s'." %
                    (self._meta.object_class.__name__, stringified_kwargs)))

        return parent_object

    def parent_cached_obj_get(self, request=None, **kwargs):
        """
        Same as the original ``cached_obj_get`` but called when a nested
        resource wants to get its parent.
        """
        cache_key = self.generate_cache_key('detail', **kwargs)
        bundle = self._meta.cache.get(cache_key)

        if bundle is None:
            bundle = self.parent_obj_get(request=request, **kwargs)
            self._meta.cache.set(cache_key, bundle)

        return bundle

    def get_via_uri_resolver(self, uri):
        """
        Do the work of the original ``get_via_uri`` except calling ``obj_get``.

        Use this as a helper function.
        """
        prefix = get_script_prefix()
        chomped_uri = uri

        if prefix and chomped_uri.startswith(prefix):
            chomped_uri = chomped_uri[len(prefix) - 1:]

        try:
            _view, _args, kwargs = resolve(chomped_uri)
        except Resolver404:
            raise NotFound("The URL provided '%s' was not a link to a valid "
                           "resource." % uri)

        return kwargs

    def get_nested_via_uri(self, uri, parent_resource,
                           parent_object, nested_name, request=None):
        """
        Obtain a nested resource from an uri, a parent resource and a parent
        object.

        Calls ``obj_get`` which handles the authorization checks.
        """
        # TODO: improve this to get parent resource & object from uri too?
        kwargs = self.get_via_uri_resolver(uri)
        return self.obj_get(nested_name=nested_name,
                            parent_resource=parent_resource,
                            parent_object=parent_object,
                            request=request,
                            **self.remove_api_resource_names(kwargs))

    def get_via_uri_no_auth_check(self, uri, request=None):
        """
        Obtain a nested resource from an uri, a parent resource and a
        parent object.

        Does *not* do authorization checks, those must be performed manually.
        This function is useful be called from custom views over a resource
        which need access to objects and can do the check of permissions
        theirselves.
        """
        kwargs = self.get_via_uri_resolver(uri)
        return self.obj_get_no_auth_check(request=request,
                        **self.remove_api_resource_names(kwargs))


    def obj_search(self, query, object_list, **kwargs):
        if not hasattr(self._meta, 'searching'):
            raise BadRequest("Searching is disabled for this resource.")
        q = Q()
        for item in self._meta.searching:
            q = (q | Q(**{item: query}))

        return object_list.filter(q).distinct()

    def filter_value_to_python(self, value, field_name, filters, filter_expr,
            filter_type):
        """
        Turn the string ``value`` into a python object.

        10to8 changes: We look for datetime queries and strip timezone.
        """
        # Simple values
        if value in ['true', 'True', True]:
            value = True
        elif value in ['false', 'False', False]:
            value = False
        elif value in ('nil', 'none', 'None', None):
            value = None

        # Split on ',' if not empty string and either an in or range filter.
        if filter_type in ('in', 'range') and len(value):
            if hasattr(filters, 'getlist'):
                value = []

                for part in filters.getlist(filter_expr):
                    value.extend(part.split(','))
            else:
                value = value.split(',')

        if isinstance(self.fields[field_name], tastypie.fields.DateTimeField):
            try:
                # Try to rip a date/datetime out of it.
                value = dateutil.parser.parse(value)
                value = convert_aware_datetime_to_naive(value).isoformat()
            except ValueError:
                raise BadRequest("Datetime provided to '%s' field doesn't appear to be a valid datetime string: '%s'" % (self.instance_name, value))


        return value

    def obj_get_list(self, request=None, **kwargs):
        """
        A ORM-specific implementation of ``obj_get_list``.

        Takes an optional ``request`` object, whose ``GET`` dictionary can be
        used to narrow the query.

        if called nested, it uses he nested_manager
        """
        filters = {}
        search = False


        if hasattr(request, 'GET'):
            # Grab a mutable copy.
            filters = request.GET.copy()
            if 'q' in request.GET.keys():
                search = True
                query = request.GET['q']
                del(filters['q'])
        cleaned_kwargs = self.real_remove_api_resource_names(kwargs)
        # Update with the provided kwargs.
        filters.update(cleaned_kwargs)
        applicable_filters = self.build_filters(filters=filters)
        generic_fields = kwargs.get('generic_fields')

        if generic_fields:
            fields = ('object_id', 'content_type')
            for field in fields:
                for kwarg in cleaned_kwargs.keys():
                    if kwarg.startswith(field):
                        applicable_filters[kwarg] = cleaned_kwargs[kwarg]

        try:
            if 'related_manager' in kwargs:
                base_object_list = kwargs['related_manager'].all()
            else:
                base_object_list = self.apply_filters(request, applicable_filters)
            if search:
                base_object_list = self.obj_search(query, base_object_list, **kwargs)
            return self.apply_proper_authorization_limits(request,
                                                base_object_list, **kwargs)
        except ValueError:
            raise BadRequest("Invalid resource lookup data provided "
                             "(mismatched type).")

    def obj_get(self, request=None, **kwargs):
        """
        Same as the original ``obj_get`` but knows when it is being called to
        get an object from a nested resource uri.

        Performs authorization checks in every case.
        """

        try:
            if 'child_object' in kwargs:
                try:
                    object_list = self.get_obj_from_parent_kwargs(**kwargs)
                    kwargs = self.real_remove_api_resource_names(kwargs)
                except AttributeError:
                    raise NotFound('Could not find child object for this resource')
            else:
                base_object_list = self.get_object_list(request).filter(
                                **self.real_remove_api_resource_names(kwargs))

                object_list = self.apply_proper_authorization_limits(request,
                                                base_object_list, **kwargs)

            stringified_kwargs = ', '.join(["%s=%s" % (k, v)
                                            for k, v in kwargs.items()])

            if len(object_list) <= 0:
                raise self._meta.object_class.DoesNotExist("Couldn't find an "
                            "instance of '%s' which matched '%s'." %
                            (self._meta.object_class.__name__,
                             stringified_kwargs))
            elif len(object_list) > 1:
                raise MultipleObjectsReturned("More than '%s' matched '%s'." %
                        (self._meta.object_class.__name__, stringified_kwargs))

            return object_list[0]
        except ValueError:
            raise NotFound("Invalid resource lookup data provided (mismatched "
                           "type).")

    def cached_obj_get(self, request=None, **kwargs):
        """
        A version of ``obj_get`` that uses the cache as a means to get
        commonly-accessed data faster.
        """
        cache_key = self.generate_cache_key('detail',
                                **self.real_remove_api_resource_names(kwargs))
        bundle = self._meta.cache.get(cache_key)

        if bundle is None:
            bundle = self.obj_get(request=request, **kwargs)
            self._meta.cache.set(cache_key, bundle)

        return bundle


    def is_valid(self, bundle, request=None, run_authorization=True):
        """
        Handles checking if the data provided by the user is valid.

        Mostly a hook, this uses class assigned to ``validation`` from
        ``Resource._meta``.

        If validation fails, an error is raised with the error messages
        serialized inside it.
        """
        if request and run_authorization:
            # Run is authorized again, but this time with the object.
            self.is_authorized(request, bundle.obj)

        errors = self._meta.validation.is_valid(bundle, request)

        if errors:
            bundle.errors[self._meta.resource_name] = errors
            return False

        return True

    def obj_create(self, bundle, request=None, **kwargs):
        """
        Nested version of object create.

        We need to validate the parent and save the clild in a different way (using the RelationshipManager).

        We also watch for our 'fail silently check' on the following exceptions:

        """
        if 'parent_resource' in kwargs:

            manager = kwargs.pop('related_manager', None)
            parent_object = kwargs.pop('parent_object', None)
            #parent_resource = kwargs.pop('parent_resource', None)
            #field_name = kwargs.pop('nested_field_name', None)
            #nested_name = kwargs.pop('nested_name', None)

            fields = manager.core_filters.keys()

            child_object_attribute = None

            generic_fields = kwargs.get('generic_fields')

            if generic_fields:
                child_object_attribute = generic_fields['manager']

            if len(fields) == 1:
                child_object_attribute = fields[0].split('__')[0]

            if manager is None or child_object_attribute is None or parent_object is None:
                raise BadRequest("Couldn't identify relationship")

            if bundle.obj is None:
                raise BadRequest("Coludn't create a base object.")
            setattr(bundle.obj, child_object_attribute, parent_object)

            exclude_keys = [child_object_attribute]

            if hasattr(manager, "content_type_field_name"):
                exclude_keys.append(manager.content_type_field_name)

            if hasattr(manager, "object_id_field_name"):
                exclude_keys.append(manager.object_id_field_name)


            for key in exclude_keys:
                if key in kwargs:
                    kwargs.pop(key)
                    continue
                for key2 in kwargs.keys():
                    if key2.startswith(key + '__'):
                        kwargs.pop(key2)
                        continue

            for key, value in kwargs.items():
                setattr(bundle.obj, key, value)

            bundle = self.full_hydrate(bundle)
            self.is_valid(bundle, request)

            if bundle.errors:
                self.error_response(bundle.errors, request)

            # Save FKs just in case.
            self.save_related(bundle)

            # Save parent, using the related manager!
            manager.add(bundle.obj)

            # Now pick up the M2M bits.
            m2m_bundle = self.hydrate_m2m(bundle)
            self.save_m2m(m2m_bundle)
            #Set fileds for uri creation
            bundle.parent_object = parent_object
            bundle.nested_name = kwargs.get('nested_name', None)
            bundle.parent_resource = kwargs.get('parent_resource', None)
            return bundle
        else:
            kwargs = self.real_remove_api_resource_names(kwargs)
            return super(ExtendedModelResource, self).obj_create(bundle, request,
                                                             **kwargs)

    def hydrate_m2m(self, bundle):
        """
        Extended here to make sure we don't wipe m2m attributes of models if they are not included in the origional data.
        For example, if a user updates a object, which has several related objects under a ToManyField. We will only clear
        the related objects that field if the user includes field_name = [] in the PUT data.
        Or, another way of putting it, we won't touch fields of at object that are not specifically set and included in the
        PUT data.
        """

        old_data = bundle.data.copy()

        m2m_bundle = super(ExtendedModelResource, self).hydrate_m2m(bundle)

        # Drop fields that havn't got blank=True set. Otherwise we'll wipe them.
        for field_name, field_obj in m2m_bundle.data.items():
            if field_name not in old_data.keys() and self.fields[field_name].blank == False:
                del m2m_bundle.data[field_name]
        del old_data
        return m2m_bundle



    def save_m2m(self, bundle):
        """
        Handles the saving of related M2M data.

        Due to the way Django works, the M2M data must be handled after the
        main instance, which is why this isn't a part of the main ``save`` bits.

        We override here to support related fields properly.
        We don't clear the manager automatically, and we offer the choice of deleting objects that are unlinked.

        """
        for field_name, field_object in self.fields.items():
            if not getattr(field_object, 'is_m2m', False):
                continue

            if not field_object.attribute:
                continue

            if field_object.readonly:
                continue
            # Get the manager.
            related_mngr = None
            if isinstance(field_object.attribute, basestring):
                related_mngr = getattr(bundle.obj, field_object.attribute)

            elif callable(field_object.attribute):
                related_mngr = field_object.attribute(bundle)

            if not related_mngr:
                continue

            if field_name not in bundle.data:
                continue

            new = []
            existing = []

            existing_objects = {}
            for obj in related_mngr.all():
                existing_objects[obj.id] = False

            related_objs = []

            for related_bundle in bundle.data[field_name]:
                if related_bundle.obj.id is None:
                    new.append(related_bundle)
                    continue
                if related_bundle.obj.id in existing_objects.keys():
                    existing_objects[related_bundle.obj.id] = True
                    existing.append(related_bundle)
                    continue
                # We have an id, but we're not existing... odd.
                new.append(related_bundle)

            to_delete = filter(lambda o: existing_objects[o] == False, existing_objects.keys())
            if len(to_delete)  > 0:
                delete_on_unlink = getattr(field_object, "delete_on_unlink", False)
                if delete_on_unlink == True:
                    related_mngr.filter(id__in=to_delete).delete()
                else:
                    for a in related_mngr.filter(id__in=to_delete):
                        related_mngr.remove(a)

            for related_bundle in existing:
                related_bundle.obj.save()

            related_mngr.add(*[n.obj for n in new])


    def get_obj_from_parent_kwargs(self, **kwargs):

        # RDH: Note: this should be called after (from) dispatch_nested, since
        # that method creates the pk (from nested_pk) and parent_pk fields, and
        # removes nested_pk. For the time being, to make sure we're being called
        # correctly:
        if 'nested_pk' in kwargs:
            raise ValueError("We were called with nested_pk, instead of pk and parent_pk")

        # Also, why are we popping everything out of dicts? Immutability = Good

        if kwargs.get('pk', None) is not None:
            manager = kwargs.pop('child_object', None)
            try:
                return manager.get(pk=kwargs.pop('pk', None))
            except self._meta.object_class.DoesNotExist:
                raise NotFound("Child object of class %s could not be found in resource %s ." % (self._meta.object_class.__name__, self._meta.resource_name))
        else:
            obj = kwargs.pop('child_object', None)

            if not isinstance(obj, self._meta.object_class):
                raise NotFound("Child object could of class %s not be found in resource %s." % (self._meta.object_class.__name__, self._meta.resource_name))

            return obj

    def obj_update(self, bundle, request=None, skip_errors=False, **kwargs):
        """
        Check if we're nested. If we are, check that we're updating a child that's related to the parent.
        If not return 404
        """
        # Are we nested?

        if 'child_object' in kwargs:
            try:
                bundle.obj = self.get_obj_from_parent_kwargs(**kwargs)
            except AttributeError:
                raise BadRequest('Could not find child object for this resource (%s)' % self._meta.resource_name)

        kwargs = self.real_remove_api_resource_names(kwargs)
        return super(ExtendedModelResource, self).obj_update(bundle, request,
                                            skip_errors=skip_errors, **kwargs)

    def obj_delete_list(self, request=None, **kwargs):
        """
        A ORM-specific implementation of ``obj_delete_list``.

        Takes optional ``kwargs``, which can be used to narrow the query.
        """
        base_object_list = self.get_object_list(request).filter(
                                **self.real_remove_api_resource_names(kwargs))
        authed_object_list = self.apply_proper_authorization_limits(request,
                                                    base_object_list, **kwargs)

        if hasattr(authed_object_list, 'delete'):
            # It's likely a ``QuerySet``. Call ``.delete()`` for efficiency.
            authed_object_list.delete()
        else:
            for authed_obj in authed_object_list:
                authed_obj.delete()

    def obj_delete(self, request=None, **kwargs):
        """
        A ORM-specific implementation of ``obj_delete``.

        Takes optional ``kwargs``, which are used to narrow the query to find
        the instance.
        """
        # Are we nested?
        if 'child_object' in kwargs:
            try:
                obj = self.get_obj_from_parent_kwargs(**kwargs)
                kwargs = self.real_remove_api_resource_names(kwargs)
            except AttributeError:
                raise NotFound('Could not find child object for this resource')

        else:
            kwargs = self.real_remove_api_resource_names(kwargs)
            obj = kwargs.pop('_obj', None)

        if not hasattr(obj, 'delete'):
            try:
                obj = self.obj_get(request, **kwargs)
            except ObjectDoesNotExist:
                raise NotFound("A model instance matching the provided arguments could not be found.")

        obj.delete()

    def obj_get_no_auth_check(self, request=None, **kwargs):
        """
        Same as the original ``obj_get`` knows when it is being called to get
        a nested resource.

        Does *not* do authorization checks.
        """
        # TODO: merge this and original obj_get and use another argument in
        #       kwargs to know if we should check for auth?
        try:
            object_list = self.get_object_list(request).filter(**kwargs)
            stringified_kwargs = ', '.join(["%s=%s" % (k, v)
                                            for k, v in kwargs.items()])

            if len(object_list) <= 0:
                raise self._meta.object_class.DoesNotExist("Couldn't find an "
                            "instance of '%s' which matched '%s'." %
                            (self._meta.object_class.__name__,
                             stringified_kwargs))
            elif len(object_list) > 1:
                raise MultipleObjectsReturned("More than '%s' matched '%s'." %
                        (self._meta.object_class.__name__, stringified_kwargs))

            return object_list[0]
        except ValueError:
            raise NotFound("Invalid resource lookup data provided (mismatched "
                           "type).")

    def apply_nested_authorization_limits(self, request, object_list,
                                               parent_resource, parent_object,
                                               nested_name):
        """
        Allows the ``Authorization`` class to further limit the object list.
        Also a hook to customize per ``Resource``.
        """
        method_name = 'apply_limits_nested_%s' % nested_name
        if hasattr(parent_resource._meta.authorization, method_name):
            method = getattr(parent_resource._meta.authorization, method_name)
            object_list = method(request, parent_object, object_list)

        return object_list

    def apply_proper_authorization_limits(self, request, object_list,
                                              **kwargs):
        """
        Decide which type of authorization to apply, if the resource is being
        used as nested or not.
        """
        parent_resource = kwargs.get('parent_resource', None)
        if parent_resource is None:  # No parent, used normally
            return self.apply_authorization_limits(request, object_list)

        # Used as nested!
        return self.apply_nested_authorization_limits(request, object_list,
                    parent_resource,
                    kwargs.get('parent_object', None),
                    kwargs.get('nested_name', None))


    def dispatch_nested_detail(self, request, **kwargs):
        return self.dispatch_nested(request, **kwargs)


    def get_generic_fields(self, generic_field_details, field_name):

        defaults = {
            'manager': 'owner',
            'object_id': 'object_id',
            'content_type': 'content_type'
        }

        if isinstance(generic_field_details, dict):
            for key in defaults.keys():
                if key not in generic_field_details:
                    generic_field_details[key] = defaults[key]
            return generic_field_details

        else:
            return defaults

    def dispatch_nested(self, request, **kwargs):
        """
        Dispatch a request to the nested resource.
        """
        # We don't check for is_authorized here since it will be
        # parent_cached_obj_get which will check that we have permissions
        # over the parent.
        self.is_authenticated(request)
        self.throttle_check(request)

        nested_name = kwargs.pop('nested_name')
        nested_pk = kwargs.pop('nested_pk', None)
        nested_field = self._nested[nested_name]

        try:
            obj = self.parent_cached_obj_get(request=request,
                        **self.remove_api_resource_names(kwargs))
        except ObjectDoesNotExist:
            return http.HttpNotFound()
        except MultipleObjectsReturned:
            return http.HttpMultipleChoices("More than one parent resource is "
                                            "found at this URI.")

        # The nested resource needs to get the api_name from its parent because
        # it is possible that the resource being used as nested is not
        # registered in the API (ie. it can only be used as nested)
        nested_resource = nested_field.to_class()
        nested_resource._meta.api_name = self._meta.api_name

        # TODO: comment further to make sense of this block
        manager = None
        try:
            if isinstance(nested_field.attribute, basestring):
                name = nested_field.attribute
                manager = getattr(obj, name, None)
            elif callable(nested_field.attribute):
                manager = nested_field.attribute(obj)
            else:
                raise fields.ApiFieldError(
                    "The model '%r' has an empty attribute '%s' \
                    and doesn't allow a null value." % (
                        obj,
                        nested_field.attribute
                    )
                )
        except ObjectDoesNotExist:
            pass

        kwargs['nested_name'] = nested_name
        kwargs['nested_field_name'] = nested_field.attribute
        kwargs['parent_resource'] = self
        kwargs['parent_object'] = obj

        if hasattr(self._meta, 'nested_generic_fields'):
            # Meta's being screwed around with... it's a tuple for some strange reason.... fixme...
            if nested_name in self._meta.nested_generic_fields[0]:
                kwargs['generic_fields'] = self.get_generic_fields(self._meta.nested_generic_fields[0][nested_name], nested_name)

        if manager is None or not hasattr(manager, 'all') or nested_pk is not None:
            dispatch_type = 'detail'
#            if nested_pk is not None:
            kwargs['parent_pk'] = kwargs['pk']
            kwargs['pk'] = nested_pk
            kwargs['child_object'] = manager
        else:
            dispatch_type = 'list'
            kwargs['related_manager'] = manager
            # 'pk' will refer to the parent, so we remove it.
            if 'pk' in kwargs:
                del kwargs['pk']
            # Update with the related manager's filters, which will link to
            # the parent. Key field for filtering.
            kwargs.update(manager.core_filters)

        return nested_resource.dispatch(
            dispatch_type,
            request,
            **kwargs
        )

    def is_authorized_nested(self, request, nested_name,
                             parent_resource, parent_object, object=None):
        """
        Handles checking of permissions to see if the user has authorization
        to GET, POST, PUT, or DELETE this resource.  If ``object`` is provided,
        the authorization backend can apply additional row-level permissions
        checking.
        """
        # We use the authorization of the parent resource
        method_name = 'is_authorized_nested_%s' % nested_name
        if hasattr(parent_resource._meta.authorization, method_name):
            method = getattr(parent_resource._meta.authorization, method_name)
            auth_result = method(request, parent_object, object)

            if isinstance(auth_result, HttpResponse):
                raise ImmediateHttpResponse(response=auth_result)

            if not auth_result is True:
                raise ImmediateHttpResponse(response=http.HttpUnauthorized())

    def dispatch(self, request_type, request, **kwargs):
        """
        Same as the usual dispatch, but knows if its being called from a nested
        resource.

        It also checks for the 'full_depth' option used on gets.

        """
        allowed_methods = getattr(self._meta,
                                  "%s_allowed_methods" % request_type, None)
        request_method = self.method_check(request, allowed=allowed_methods)

        method = getattr(self, "%s_%s" % (request_method, request_type), None)

        if method is None:
            raise ImmediateHttpResponse(response=http.HttpNotImplemented())

        self.is_authenticated(request)
        self.throttle_check(request)

        # Has the user requsted that relationships are returned in full?
        request.full_depth = 0
        if request_method == 'get':
            if request.GET.get('full_depth', None):
                try:
                    depth = int(request.GET['full_depth'])
                    if depth < 0 > 999:
                        raise BadRequest("full_depth argument must be an interger >= 0.")
                    request.full_depth = depth
                except ValueError:
                    raise BadRequest("full_depth argument must be an interger.")

        parent_resource = kwargs.get('parent_resource', None)
        if parent_resource is None:
            self.is_authorized(request)
        else:
            self.is_authorized_nested(request, kwargs['nested_name'],
                                      parent_resource,
                                      kwargs['parent_object'])

        # All clear. Process the request.
        request = convert_post_to_put(request)

        response = method(request, **kwargs)

        # Add the throttled request.
        self.log_throttled_access(request)

        # If what comes back isn't a ``HttpResponse``, assume that the
        # request was accepted and that some action occurred. This also
        # prevents Django from freaking out.

        if not isinstance(response, HttpResponse):
            return http.HttpNoContent()


        return response


    def put_detail(self, request, update_only=False, **kwargs):
        """
        Either updates an existing resource or creates a new one with the
        provided data.

        Calls ``obj_update`` with the provided data first, but falls back to
        ``obj_create`` if the object does not already exist.

        If a new resource is created, return ``HttpCreated`` (201 Created).
        If ``Meta.always_return_data = True``, there will be a populated body
        of serialized data.

        If an existing resource is modified and
        ``Meta.always_return_data = False`` (default), return ``HttpNoContent``
        (204 No Content).
        If an existing resource is modified and
        ``Meta.always_return_data = True``, return ``HttpAccepted`` (202
        Accepted).
        """
        deserialized = self.deserialize(request, request.raw_post_data, format=request.META.get('CONTENT_TYPE', 'application/json'))
        deserialized = self.alter_deserialized_detail_data(request, deserialized)
        bundle = self.build_bundle(data=dict_strip_unicode_keys(deserialized), request=request)

        try:
            updated_bundle = self.obj_update(bundle, request=request, **self.remove_api_resource_names(kwargs))

            if not self._meta.always_return_data:
                return http.HttpNoContent()
            else:
                updated_bundle = self.full_dehydrate(updated_bundle)
                updated_bundle = self.alter_detail_data_to_serialize(request, updated_bundle)
                return self.create_response(request, updated_bundle, response_class=http.HttpAccepted)
        except (NotFound, MultipleObjectsReturned):
            if not update_only:
                updated_bundle = self.obj_create(bundle, request=request, **self.remove_api_resource_names(kwargs))
                location = self.get_resource_uri(updated_bundle)

                if not self._meta.always_return_data:
                    return http.HttpCreated(location=location)
                else:
                    updated_bundle = self.full_dehydrate(updated_bundle)
                    updated_bundle = self.alter_detail_data_to_serialize(request, updated_bundle)
                    return self.create_response(request, updated_bundle, response_class=http.HttpCreated, location=location)
            else:
                raise NotFound


    def get_list(self, request, **kwargs):
        """
        Returns a serialized list of resources.

        Calls ``obj_get_list`` to provide the data, then handles that result
        set and serializes it.

        Should return a HttpResponse (200 OK).

        10to8 change:
            - We override here to inject our 'full_depth' attribute into bundles.
            - Hooks for caching
        """

        def update_cache(data, date):

            # keys: (dates_hash, data_hash, id)
            # args: (value, date(seconds))
            func = '''local cache_date = nil
            cache_date = redis.call("HGET", KEYS[1], KEYS[3])
            if cache_date == nil then
                cache_date = 0
            elseif cache_date == false then
                cache_date = 0
            end
            if tonumber(cache_date) < tonumber(ARGV[2]) then
                redis.call("HSET", KEYS[2], KEYS[3], ARGV[1])
                redis.call("HSET", KEYS[1], KEYS[3], ARGV[2])
                return true
            else
                return false
            end
            '''

            print "Updating %s cache elements" % len(data)
            import redis
            r = redis.StrictRedis(host='localhost', port=6379, db=0)
            set_cache = r.register_script(func)
            pipe = r.pipeline()
            for i in data.keys():
                set_cache(
                    keys=["%s/%s/dates" % (self._meta.api_name, self._meta.resource_name), "%s/%s/data" % (self._meta.api_name, self._meta.resource_name), i],
                    args=[data[i], date.strftime("%s")],
                    client=pipe
                )

            print pipe.execute()
            #pipe = r.pipeline()
            #pipe.hmset("%s/%s/data" % (self._meta.api_name, self._meta.resource_name), data)
            #pipe.hmset("%s/%s/dates" % (self._meta.api_name, self._meta.resource_name), dates)
            #pipe.execute()

        def get_cached_response(ids):
            import redis
            r = redis.StrictRedis(host='localhost', port=6379, db=0)
            pipe = r.pipeline()
            pipe.hmget("%s/%s/data" % (self._meta.api_name, self._meta.resource_name), ids)
            pipe.hmget("%s/%s/dates" % (self._meta.api_name, self._meta.resource_name), ids)
            data, dates = pipe.execute()

            if not len(data) == len(dates):
                print "data and dates returned from cache are different lengths, this isn't good."
                return [], ids

            for i in range(len(dates)):
                print dates[i]
                if dates[i] is None or dates[i] == "None":
                    dates[i] = None
                    data[i] = None
                elif data[i] is None or data[i] == "None":
                    data[i] = None
                    dates[i] = None
            return data, dates


        def get_non_cached(objects_to_serialise):

        # Dehydrate the bundles in preparation for serialization.
        bundles = [self.build_bundle(obj=obj, request=request) for obj in to_be_serialized['objects']]
        #10to8 change:
        set_full_depth = lambda b: setattr(b, 'full_depth', request.full_depth)
        map(set_full_depth, bundles)

        if 'nested_name' in kwargs and 'parent_object' in kwargs and 'parent_resource' in kwargs:
            set_parent_resource  = lambda b: setattr(b, 'parent_resource', kwargs['parent_resource'])
            set_nested_name = lambda b: setattr(b, 'nested_name', kwargs['nested_name'])
            set_parent_object = lambda b: setattr(b, 'parent_object', kwargs['parent_object'])
            map(set_parent_resource, bundles)
            map(set_nested_name, bundles)
            map(set_parent_object, bundles)

            return [self.full_dehydrate(bundle) for bundle in bundles]

        objects = self.obj_get_list(request=request, **self.remove_api_resource_names(kwargs))
        sorted_objects = self.apply_sorting(objects, options=request.GET)

        bundle = Bundle()
        if 'nested_name' in kwargs and 'parent_object' in kwargs and 'parent_resource' in kwargs:
            bundle.parent_resource = kwargs['parent_resource']
            bundle.parent_object = kwargs['parent_object']
            bundle.nested_name = kwargs['nested_name']

        paginator = self._meta.paginator_class(request.GET, sorted_objects, resource_uri=self.get_resource_uri(bundle),
            limit=self._meta.limit, max_limit=self._meta.max_limit, collection_name=self._meta.collection_name)

        to_be_serialized = paginator.page()

        if getattr(self._meta, 'redis_cache', False):
            print "REDIS CACHE ENABLED FOR RESOURCE %s" % self._meta.resource_name
            # Query just the ids we should be returning
            ids_to_get = list(to_be_serialized['objects'].values_list('id', flat=True))

            # Look in the cache, return matches.
            existing_data, existing_data_dates = get_cached_response(ids_to_get)

            missing_ids = []

            # Work out what we're missing
            for i in range(len(ids_to_get)):
                if existing_data_dates[i] is None or existing_data[i] is None:
                    missing_ids.append(ids_to_get[i])
            total = len(ids_to_get)
            misses = len(missing_ids)
            hits = total - misses
            print "Cache Stats: %s - %s hits, %s misses." % ((hits/total)*100, hits, misses)

            # Fetch any objects we're missing
            if misses > 0:
                fetch_time = datetime.datetime.utcnow()
                #TODO: this dosen't seem to filter on ids only.... 
                un_cached_bundles = get_non_cached(objects.filter(id__in=missing_ids))
                desired_format = self.determine_format(request)
                print "Got %s un_cached_bundles" % len(un_cached_bundles)
                for bundle in un_cached_bundles:
                    serialized_bundle = self.serialize(request, bundle, desired_format)
                    existing_data[ids_to_get.index(bundle.obj.id)] = serialized_bundle

            # Build our serialised object.
            desired_format = self.determine_format(request)
            serialized_meta = self.serialize(request, to_be_serialized['meta'], desired_format)
            serialised_objects = '[ ' + (''.join([obj + ', ' for obj in existing_data])).rstrip(', ') + ' ]'

            # Shove our serialised objects into the cache, updating dates too.

            update_data = {}
            if misses > 0:
                for id in missing_ids:
                    update_data[id] = existing_data[ids_to_get.index(id)]
                update_cache(update_data, fetch_time)

            return HttpResponse(content='{ "meta": %s, "objects": %s}' % (serialized_meta, serialised_objects), content_type=build_content_type(desired_format))

        else:
            to_be_serialized['objects'] = get_non_cached(to_be_serialized['objects'])
        to_be_serialized = self.alter_list_data_to_serialize(request, to_be_serialized)
        return self.create_response(request, to_be_serialized)


    def get_detail(self, request, **kwargs):
        """
        Returns a single serialized resource.

        Calls ``cached_obj_get/obj_get`` to provide the data, then handles that
        result set and serializes it.

        Should return a HttpResponse (200 OK).

        10to8 change:
            - We override here to inject our 'full_depth' attribute into bundles.

        """
        try:
            # If call was made through Nested we should already have the
            # child object.
        # Are we nested?
            if 'child_object' in kwargs:
                try:
                    obj = self.get_obj_from_parent_kwargs(**kwargs)
                except AttributeError:
                    raise NotFound('Could not find child object for this resource')
            else:
                obj = self.cached_obj_get(request=request,
                                    **self.remove_api_resource_names(kwargs))
        except AttributeError:
            return http.HttpNotFound()
        except ObjectDoesNotExist:
            return http.HttpNotFound()
        except MultipleObjectsReturned:
            return http.HttpMultipleChoices("More than one resource is found "
                                            "at this URI.")

        bundle = self.build_bundle(obj=obj, request=request)
        bundle.full_depth = request.full_depth

        if 'nested_name' in kwargs and 'parent_object' in kwargs and 'parent_resource' in kwargs:
            bundle.parent_resource = kwargs['parent_resource']
            bundle.parent_object = kwargs['parent_object']
            bundle.nested_name = kwargs['nested_name']

        bundle = self.full_dehydrate(bundle)
        bundle = self.alter_detail_data_to_serialize(request, bundle)
        return self.create_response(request, bundle)

    def post_list(self, request, **kwargs):
        """
        We manage nested creation inside create_object
        """
        return super(ExtendedModelResource, self).post_list(request, **kwargs)

    def put_list(self, request, **kwargs):
        """
        Unsupported if used as nested. Otherwise, same as original.
        """
        if 'parent_resource' in kwargs:
            raise NotImplementedError('You cannot put a list on a nested'
                                      ' resource.')
        return super(ExtendedModelResource, self).put_list(request, **kwargs)

    def patch_list(self, request, **kwargs):
        """
        Unsupported if used as nested. Otherwise, same as original.
        """
        if 'parent_resource' in kwargs:
            raise NotImplementedError('You cannot patch a list on a nested'
                                      ' resource.')
        return super(ExtendedModelResource, self).patch_list(request, **kwargs)

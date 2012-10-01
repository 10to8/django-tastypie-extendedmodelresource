"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""
from django.contrib.auth.models import User

from django.test import LiveServerTestCase

import requests
import simplejson
from api.models import Entry


class SimpleTest(LiveServerTestCase):
    fixtures = 'initial_data'


    def test_get_list(self):
        result = requests.get(self.live_server_url + '/api/v1/user/2/entries/')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(simplejson.loads(result.text)['objects']), 1)


    def test_get_list_filter(self):
        user = User.objects.get(id=2)
        e = Entry(user=user, title='filter_me')
        e.save()

        result = requests.get(self.live_server_url + '/api/v1/user/2/entries/?title__startswith=filter')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(simplejson.loads(result.text)['objects']), 1)

        result = requests.get(self.live_server_url + '/api/v1/user/2/entries/')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(simplejson.loads(result.text)['objects']), 2)

    def test_get_detail(self):
        result = requests.get(self.live_server_url + '/api/v1/user/2/entries/1/')
        self.assertEqual(result.status_code, 200)



    def test_post_detail_does_not_exist(self):
        headers = {'Content-Type': 'application/json',}
        request_url = self.live_server_url + '/api/v1/user/2/entries/9999/'
        data = {'body': "hello, this is the body"}
        result = requests.put(request_url, data=simplejson.dumps(data), headers=headers)
        self.assertEqual(result.status_code, 400)

    def test_post_detail(self):
        headers = {'Content-Type': 'application/json',}
        old_entry = Entry.objects.get(id=1)
        request_url = self.live_server_url + '/api/v1/user/2/entries/1/'
        data = {'body': "hello, this is the body"}
        result = requests.put(request_url, data=simplejson.dumps(data), headers=headers)
        self.assertEqual(result.status_code, 204) # Updated
        entry = Entry.objects.get(id=1)
        self.assertEqual(entry.body, data['body'])

        for key in entry.__dict__.keys():
            if not key == 'body' and not key.startswith('_'):
                self.assertEqual(entry.__dict__[key], old_entry.__dict__[key])

    def test_post_detail_non_relation(self):
        new_entry = Entry(body='test', title='test', user=User.objects.get(id=1))
        new_entry.save()

        headers = {'Content-Type': 'application/json',}
        request_url = self.live_server_url + '/api/v1/user/2/entries/%s/' % new_entry.id
        data = {'body': "hello, this is the body"}
        result = requests.put(request_url, data=simplejson.dumps(data), headers=headers)
        self.assertEqual(result.status_code, 400)

    def test_post_list(self):
        headers = {'Content-Type': 'application/json',}
        request_url = self.live_server_url + '/api/v1/user/2/entries/'

        data = {'body': "hello, this is the body"}
        result = requests.post(request_url, data=simplejson.dumps(data), headers=headers)
        self.assertEqual(result.status_code, 201) # Created

        entry = Entry.objects.all()
        entry = entry[len(entry)-1]
        self.assertEqual(entry.body, data['body'])
        self.assertEqual(entry.user, User.objects.get(id=2))
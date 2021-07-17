#!/usr/bin/env python3

"""Public API constraints and restrictions

The Public API is limited to 500 requests per day and a rate of 4 requests per minute.  # noqa
The Public API must not be used in commercial products or services.
The Public API must not be used in business workflows that do not contribute new files. # noqa
You are not allowed to register multiple accounts to overcome the aforementioned limitations.   # noqa

.. _reference:
    https://developers.virustotal.com/v3.0/reference#overview
"""

import requests
import urllib.parse
from typing import Union


class VirusTotal:
    """VirusTotal (ver3) Module"""

    def __init__(self, apikey: str, _license: Union[bool] = False) -> None:
        """Initialization

        :param apikey: api key
        :type apikey: str
        :param _license: if premium license, set True otherwise False
        :type _license: bool
        """

        # baseurl
        self.base = 'https://www.virustotal.com/api/v3/'
        # request header
        self.headers = {'x-apikey': apikey}
        # TODO: Distinguish Premium/Public License
        if _license:
            self.license = True

    def _api_request(self, method: str, url: str) -> dict:
        """API Request

        :param method: Request method (GET or POST)
        :type method: str
        :param url: URL to api request
        :type url: str
        """

        response = requests.request(method=method, url=url,
                                    headers=self.headers)
        return response.json()

    def file_scan(self, id: str):
        """Retrieve information about a file

        :param id: SHA-256, SHA-1 or MD5 identifying the file
        :type id: str
        """

        url = urllib.parse.urljoin(base=self.base, url=f'files/{id}',
                                   allow_fragments=True)

        return self._api_request(method='GET', url=url)

    def url_scan(self, id: str):
        """Retrieve information about a URL

        :param id: URL identifier or base64 representation of URL to scan
        :type id: str
        """

        url = urllib.parse.urljoin(base=self.base, url=f'urls/{id}',
                                   allow_fragments=True)

        return self._api_request(method='GET', url=url)

    def domain_scan(self, domain: str):
        """Retrieve information about an Internet domain

        :param domain: Domain name
        :type domain: str
        """

        url = urllib.parse.urljoin(base=self.base, url=f'domains/{domain}',
                                   allow_fragments=True)

        return self._api_request(method='GET', url=url)

    def ip_scan(self, ip: str):
        """Retrieve information about an IP address

        :param ip: IP address
        :type ip: str
        """

        url = urllib.parse.urljoin(base=self.base, url=f'ip_addresses/{ip}',
                                   allow_fragments=True)

        return self._api_request(method='GET', url=url)


class BadRequestError(Exception):
    """The API request is invalid or malformed.
    The message usually provides details about why the request is not valid."""
    def __init__(self, *args, **kwargs):
        pass


class InvalidArgumentError(Exception):
    """Some of the provided arguments are incorrect."""
    def __init__(self, *args, **kwargs):
        pass


class NotAvailableYet(Exception):
    """The resource is not available yet, but will become available later."""
    def __init__(self, *args, **kwargs):
        pass


class UnselectiveContentQueryError(Exception):
    """Content search query is not selective enough."""
    def __init__(self, *args, **kwargs):
        pass


class UnsupportedContentQueryError(Exception):
    """Content search query is not selective enough."""
    def __init__(self, *args, **kwargs):
        pass


class AuthenticationRequiredError(Exception):
    """The operation requires an authenticated user.
    Verify that you have provided your API key."""
    def __init__(self, *args, **kwargs):
        pass


class UserNotActiveError(Exception):
    """The user account is not active. 
    Make sure you properly activated your account by following the link sent to your email."""  # noqa
    def __init__(self, *args, **kwargs):
        pass


class WrongCredentialsError(Exception):
    """The provided API key is incorrect."""
    def __init__(self, *args, **kwargs):
        pass


class ForbiddenError(Exception):
    """You are not allowed to perform the requested operation."""
    def __init__(self, *args, **kwargs):
        pass


class NotFoundError(Exception):
    """The requested resource was not found."""
    def __init__(self, *args, **kwargs):
        pass


class AlreadyExistsError(Exception):
    """The resource already exists."""
    def __init__(self, *args, **kwargs):
        pass


class FailedDependencyError(Exception):
    """The request depended on another request and that request failed."""
    def __init__(self, *args, **kwargs):
        pass


class QuotaExceededError(Exception):
    """You have exceeded one of your quotas (minute, daily or monthly). 
    Daily quotas are reset every day at 00:00 UTC.
    You may have run out of disk space and/or number of files on your VirusTotal Monitor account."""    # noqa
    def __init__(self, *args, **kwargs):
        pass


class TooManyRequestsError(Exception):
    """Too many requests."""
    def __init__(self, *args, **kwargs):
        pass


class TransientError(Exception):
    """Transient server error. Retry might work."""
    def __init__(self, *args, **kwargs):
        pass


class DeadlineExceededError(Exception):
    """The operation took too long to complete."""
    def __init__(self, *args, **kwargs):
        pass

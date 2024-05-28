import time
from datetime import datetime

from pytz import timezone


class DateFormatter:

  @staticmethod
  def from_string(time_str):
    """
    desc: get datetime object with time string formatted as '%Y-%m-%d %H:%M:%S'
    arg0: (string) time
    ex) datetime object
    print(date_time.year)
    print(date_time.month)
    print(date_time.day)
    print(date_time.hour)
    print(date_time.minute)
    print(date_time.second)
    """
    return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')

  @staticmethod
  def current_datetime():
    """
    desc: get current datetime
    return: (string) datetime formatted as '%Y-%m-%d %H:%M:%S'
    :return:
    """
    dt = datetime.now(timezone('Asia/Seoul'))
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

  @staticmethod
  def current_datetime_object():
    """
    current datetime object
    :return: (datetime.datetime)
    """
    return datetime.now(timezone('Asia/Seoul'))

  @staticmethod
  def to_datetime(dt: str):
    """
    to datetime
    :param dt: (str) format '%Y-%m-%dT%H:%M:%SZ'
    :return:
    """
    try:
      return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
      return datetime.strptime(dt, '%Y-%m-%d')

  @staticmethod
  def current_datetime_ms():
    """
    desc: get current datetime with decimal point in second
    return: (string) datetime formatted as '%Y-%m-%d %H:%M:%S.%f'
    :return:
    """
    dt = datetime.now(timezone('Asia/Seoul'))
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')

  @staticmethod
  def get_elapsed_time(v1, v2):
    """
    desc: get elapsed time between v1, v2(past)
    arg0: (datetime) v1
    arg1: (datetime) v2
    return: (float) time difference as seconds
    :param v1:
    :param v2:
    :return:
    """
    elapsed_time = v1 - v2
    return elapsed_time.total_seconds()

  @staticmethod
  def datetime_to_str(val):
    """
    convert datetime to str
    :param val: (datetime)
    :return: (str) formatted as '%Y-%m-%d %H:%M:%S.%f'
    """
    if val is None:
      return None

    if type(val) != datetime:
      raise TypeError('Invalid val type. You must input datetime as val')
    return val.strftime('%Y-%m-%d %H:%M:%S.%f')

  @staticmethod
  def str_to_datetime_to_str(val):
    """
    convert datetime to str
    :param val(str): %Y-%m-%d"
    :return: (str) formatted as '%Y-%m-%d %H:%M:%S.%f'
    """
    if val is None:
      return None

    return DateFormatter.to_datetime(val).strftime('%Y-%m-%d %H:%M:%S.%f')


  @staticmethod
  def to_timestamp(val: str):
    """
    convert to timestamp(time.time())
    :param val:
    :return: time.time()
    """
    try:
      return time.mktime(datetime.strptime(val, '%Y-%m-%dT%H:%M:%SZ').timetuple())
    except ValueError:
      return time.mktime(datetime.strptime(val, '%Y-%m-%d').timetuple())

# example codes
# date_time_str = DateFormatter.current_datetime()
# print(date_time_str)
# date_time = DateFormatter.from_string(date_time_str)
#
# now_time = datetime.now()
# past_time = date_time
# elasped_time = now_time - past_time
# print(elasped_time.total_seconds())

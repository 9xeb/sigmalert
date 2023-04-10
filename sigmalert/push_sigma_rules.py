#!/usr/local/bin/python3.11

import time
import yaml
import glob
import json
import os
import threading
from datetime import datetime
import hashlib
import sys

from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Text, DateTime, ForeignKey, text, select, update
from sqlalchemy.ext.declarative import declarative_base


# sqlalchemy ORM magic
Base = declarative_base()
#class Logs(Base):
    #__tablename__ = 'logs'
    #id = Column(Text, primary_key = True)
    #timestamp = Column(Text)
    #host = Column(Text, primary_key = True)
    #program = Column(Text)
    #message = Column(Text)

class SigmaRules(Base):
  __tablename__ = 'sigma_rules'
  id = Column(Text, primary_key = True)
  name = Column(Text)
  description = Column(Text)
  severity = Column(Text)

#class SigmaTags(Base):
  #__tablename__ = 'sigma_tags'
  #name = Column(String, primary_key=True)

class SigmaTaggings(Base):
  __tablename__ = 'sigma_taggings'
  name = Column(Text, primary_key = True)
  rule_id = Column(Text, ForeignKey('sigma_rules.id'), primary_key = True)

class SigmaMatches(Base):
  __tablename__ = 'sigma_matches'
  rule_id = Column(Text, ForeignKey('sigma_rules.id'), primary_key = True)
  log_id = Column(Text, primary_key = True)

class SigmaFalsePositives(Base):
  __tablename__ = 'sigma_false_positives'
  rule_id = Column(Text, ForeignKey('sigma_rules.id'), primary_key = True)
  name = Column(Text, primary_key = True)

class SigmaDiamond(Base):
  __tablename__ = 'sigma_diamond'
  timestamp = Column(DateTime, primary_key = True)
  rule_id = Column(Text, ForeignKey('sigma_rules.id'), primary_key = True)
  vector = Column(Text)
  victim = Column(Text, primary_key = True)
  #reason = Column(Text)
  log = Column(Text)


class SigmaLoader():
  def __init__(self, db_engine = None, db_session = None, db_lock = None):

    #self.elastalert_rules = self.load_elastalert_rules(glob.glob('/opt/elastalert/rules/*.yaml'))
    #print("[elastalert] %s" % self.elastalert_rules)
    #print("[sigma] %s" % self.sigma_rules)
    
    self.db_user = os.environ['DB_USER']
    self.db_password = os.environ['DB_PASSWORD']
    
    self.db_engine = create_engine('postgresql+psycopg2://%s:%s@threatintel-database/threatintel' % (self.db_user, self.db_password))
    self.db_session_factory = sessionmaker(bind=self.db_engine)
    self.db_session = scoped_session(self.db_session_factory)

    # DB setup from caller
    #self.db_engine = db_engine
    #self.db_session = db_session
    #self.db_lock = db_lock

    # Create sigma tables
    #with self.db_lock:
      #print("[sigma] Lock", file=sys.stderr, flush=True)
    Base.metadata.create_all(self.db_engine)
    #print("[sigma] Unlock", file=sys.stderr, flush=True)
    self.sigma_rules = self.load_sigma_rules(glob.glob('/opt/elastalert/sigma/rules/**/*.yml', recursive=True))


  # TODO: sqlite3.IntegrityError except, instead of generic Exception. This way we can filter out expected integrity errors from actual malfunctioning

  def update_rule(self, rule):
    with self.db_session() as session:
      try:
        if len(session.execute(select(SigmaRules).where(SigmaRules.id == rule['id'])).all()) == 0:
            session.add(SigmaRules(id = rule['id'], name = rule['title'], description = rule['description'], severity = rule['level']))
            session.commit()
      except Exception as e:
        print("[sigma update rule] %s (%s)" % (e, rule), file=sys.stderr, flush=True)

  def update_tags(self, rule_id, tag):
    with self.db_session() as session:
      try:
        if len(session.execute(select(SigmaTaggings).where(SigmaTaggings.name == tag, SigmaTaggings.rule_id == rule_id)).all()) == 0:
            session.add(SigmaTaggings(name = tag, rule_id = rule_id))
            session.commit()
      except Exception as e:
        print("[sigma update tags] %s (%s,%s)" % (e, rule_id, tag), file=sys.stderr, flush=True)

  def update_false_positive(self, rule_id, falsepositive):
    with self.db_session() as session:
      try:
        if len(session.execute(select(SigmaFalsePositives).where(SigmaFalsePositives.rule_id == rule_id, SigmaFalsePositives.name == falsepositive)).all()) == 0:
            session.add(SigmaFalsePositives(rule_id = rule_id, name = falsepositive))
            session.commit()
      except Exception as e:
        print("[sigma update falsepositives] %s (%s,%s)" % (e, rule_id, falsepositive), file=sys.stderr, flush=True)

  def load_sigma_rules(self, filenames):
    #rules_map = {}
    rules_ids = []
    rulefiles_to_remove = []
    for filename in filenames:
      with open(filename, 'r') as sigma_rule:
        rule = yaml.safe_load(sigma_rule)
        #rules_map[rule['id'] + '-' + rule['title']] = rule
        rule['id'] = rule['id'] + '-' + rule['title'].replace(" ", "-")
        if rule['id'] not in rules_ids:
          rules_ids.append(rule['id'])
          print("%s" % rule['id'], file=sys.stderr, flush=True)
          self.update_rule(rule)
          try:
              for falsepositive in rule['falsepositives']:
                  self.update_false_positive(rule['id'], falsepositive)
          except Exception as e:
              print("[sigma] %s" % e, file=sys.stderr, flush=True)
          try:
              for tag in rule['tags']:
                  self.update_tags(rule['id'], tag)
          except Exception as e:
              print("[sigma] %s" % e, file=sys.stderr, flush=True)
        else:
          rulefiles_to_remove.append(filename)
    for filename in rulefiles_to_remove:
      print("[sigma] Removed rule: %s" % filename, file=sys.stderr, flush=True)
      os.remove(filename)
    #return rules_map

sigmarunner = SigmaLoader()
#sigmarunner.load_sigma_rules()


#rules_pattern = '/sigma/rules/**/*.yml'
#es_rules_pattern = '/sigma/rules/**/*.es'
#sigma_runner = SigmaRunner(rules_pattern = es_rules_pattern, time_target = 60)

#for item in sigma_runner.scan_elastic():
#  print("%s" % json.dumps(item))

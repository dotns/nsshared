"""Fixture producers. Each module defines CRATE, GROUP, TITLE, SPEC, EXTERNAL and
vectors(), or FORMAT = "json" and document(); register a new producer in PRODUCERS.

GROUP is the fixture path below `crates/<CRATE>/tests/vectors/`, matching the test
module that reads it. SPEC names the specification in this repository and EXTERNAL
the sections of the external docs; either may be None.
"""

from nsvec.producers.control.account.control import fenced_gateway as control_account_control_fenced_gateway
from nsvec.producers.identity import discovery as identity_discovery
from nsvec.producers.identity import identity as identity_identity
from nsvec.producers.identity import record as identity_record
from nsvec.producers.relay import packet as relay_packet
from nsvec.producers.rendezvous import hello as rendezvous_hello
from nsvec.producers.rendezvous import mailbox as rendezvous_mailbox
from nsvec.producers.rendezvous import registry as rendezvous_registry
from nsvec.producers.rendezvous import registry_state as rendezvous_registry_state
from nsvec.producers.control.account.control import envelope as control_account_control_envelope
from nsvec.producers.control.account.control import exchange as control_account_control_exchange
from nsvec.producers.control.account.control import node_l3_route_admission as control_account_control_node_l3_route_admission
from nsvec.producers.control.account.control import node_l3_status as control_account_control_node_l3_status
from nsvec.producers.control.account.control import node_liveness as control_account_control_node_liveness
from nsvec.producers.control.account.control import node_posture as control_account_control_node_posture
from nsvec.producers.control.account.control import reports as control_account_control_reports
from nsvec.producers.control.account.control import service_control as control_account_control_service_control
from nsvec.producers.control.account.edge import anonymous as control_account_edge_anonymous
from nsvec.producers.control.account.edge import auth as control_account_edge_auth
from nsvec.producers.control.account.edge import floor_text as control_account_edge_floor_text
from nsvec.producers.control.account.edge import material_request as control_account_edge_material_request
from nsvec.producers.control.account.edge import routing as control_account_edge_routing
from nsvec.producers.control.account.grants import grant_authority as control_account_grants_grant_authority
from nsvec.producers.control.account.node import enrollment as control_account_node_enrollment
from nsvec.producers.control.account import profile as control_account_profile
from nsvec.producers.control.account.publication import delivery as control_account_publication_delivery
from nsvec.producers.control.account.publication import envelope as control_account_publication_envelope
from nsvec.producers.control.account.publication import snapshot_pending_boundaries as control_account_publication_snapshot_pending_boundaries
from nsvec.producers.control.account.publication import snapshot_request as control_account_publication_snapshot_request
from nsvec.producers.control.account.publication import source_selection as control_account_publication_source_selection
from nsvec.producers.control.account.publication import subscription as control_account_publication_subscription
from nsvec.producers.control.account.realm import claims as control_account_realm_claims
from nsvec.producers.control.account.realm import membership as control_account_realm_membership
from nsvec.producers.control.account.realm import peers as control_account_realm_peers
from nsvec.producers.control.account.relay import admission_snapshot as control_account_relay_admission_snapshot
from nsvec.producers.control.account.relay import participant_roster as control_account_relay_participant_roster
from nsvec.producers.control.account.relay import session as control_account_relay_session
from nsvec.producers.control.account.subnet import mapping as control_account_subnet_mapping
from nsvec.producers.control.account.subnet import mapping_actions as control_account_subnet_mapping_actions
from nsvec.producers.control.account.subnet import report as control_account_subnet_report
from nsvec.producers.control.account.subnet import selection as control_account_subnet_selection
from nsvec.producers.control.account.subnet import views as control_account_subnet_views
from nsvec.producers.control.account.usage import catalog as control_account_usage_catalog
from nsvec.producers.control.account.usage import reports as control_account_usage_reports
from nsvec.producers.control.account.usage import retention as control_account_usage_retention
from nsvec.producers.control.node_control import messages as control_node_control_messages
from nsvec.producers.control.service import canonical as control_service_canonical

PRODUCERS = [
    control_account_control_fenced_gateway,
    identity_discovery,
    identity_identity,
    identity_record,
    relay_packet,
    rendezvous_hello,
    rendezvous_mailbox,
    rendezvous_registry,
    rendezvous_registry_state,
    control_account_control_envelope,
    control_account_control_exchange,
    control_account_control_node_l3_route_admission,
    control_account_control_node_l3_status,
    control_account_control_reports,
    control_account_control_node_liveness,
    control_account_control_node_posture,
    control_account_control_service_control,
    control_account_edge_anonymous,
    control_account_edge_auth,
    control_account_edge_floor_text,
    control_account_edge_material_request,
    control_account_edge_routing,
    control_account_grants_grant_authority,
    control_account_node_enrollment,
    control_account_profile,
    control_account_publication_delivery,
    control_account_publication_envelope,
    control_account_publication_snapshot_pending_boundaries,
    control_account_publication_snapshot_request,
    control_account_publication_source_selection,
    control_account_publication_subscription,
    control_account_realm_claims,
    control_account_realm_membership,
    control_account_realm_peers,
    control_account_relay_admission_snapshot,
    control_account_relay_participant_roster,
    control_account_relay_session,
    control_account_subnet_mapping,
    control_account_subnet_mapping_actions,
    control_account_subnet_report,
    control_account_subnet_selection,
    control_account_subnet_views,
    control_account_usage_catalog,
    control_account_usage_reports,
    control_account_usage_retention,
    control_node_control_messages,
    control_service_canonical,
]

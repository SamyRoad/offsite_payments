require 'test_helper'

class RedsysTest < Test::Unit::TestCase
  include OffsitePayments::Integrations

  def test_notification_method
    assert_instance_of Redsys::Notification, Redsys.notification('name=cody')
  end
end

require 'nokogiri'

module OffsitePayments
  module Integrations
    module Redsys
      mattr_accessor :service_test_url
      self.service_test_url = "https://sis-t.redsys.es:25443/sis/realizarPago"
      mattr_accessor :service_production_url
      self.service_production_url = "https://sis.redsys.es/sis/realizarPago"

      mattr_accessor :operations_test_url
      self.operations_test_url = "https://sis-t.redsys.es:25443/sis/operaciones"
      mattr_accessor :operations_production_url
      self.operations_production_url = "https://sis.redsys.es/sis/operaciones"

      def self.service_url 
        mode = OffsitePayments.mode
        case mode
        when :production
          self.service_production_url
        when :test
          self.service_test_url
        else
          raise StandardError, "Integration mode set to an invalid value: #{mode}"
        end
      end

      def self.operations_url
        mode = OffsitePayments.mode
        case mode
        when :production
          self.operations_production_url
        when :test
          self.operations_test_url
        else
          raise StandardError, "Integration mode set to an invalid value: #{mode}"
        end
      end

      def self.notification(post)
        Notification.new(post)
      end

      def self.currency_code(name)
        row = supported_currencies.assoc(name)
        row.nil? ? supported_currencies.first[1] : row[1]
      end

      def self.currency_from_code(code)
        row = supported_currencies.rassoc(code)
        row.nil? ? supported_currencies.first[0] : row[0]
      end

      def self.language_code(name)
        row = supported_languages.assoc(name.to_s.downcase.to_sym)
        row.nil? ? supported_languages.first[1] : row[1]
      end

      def self.language_from_code(code)
        row = supported_languages.rassoc(code)
        row.nil? ? supported_languages.first[0] : row[0]
      end

      def self.transaction_code(name)
        row = supported_transactions.assoc(name.to_sym)
        row.nil? ? supported_transactions.first[1] : row[1]
      end
      def self.transaction_from_code(code)
        row = supported_transactions.rassoc(code.to_s)
        row.nil? ? supported_transactions.first[0] : row[0]
      end

      def self.supported_currencies
        [ 
          ['EUR', '978'],
          ['USD', '840'],
          ['GBP', '826'],
          ['JPY', '392']
        ]
      end

      def self.supported_languages
        [
          [:xx, '000'],
          [:es, '001'],
          [:en, '002'],
          [:ca, '003'],
          [:fr, '004'],
          [:de, '005'],
          [:nl, '006'],
          [:it, '007'],
          [:sv, '008'],
          [:pt, '009'],
          [:pl, '011'],
          [:gl, '012'],
          [:eu, '013'],
        ]
      end

      def self.supported_transactions
        [
          [:authorization,              '0'],
          [:preauthorization,           '1'],
          [:confirmation,               '2'],
          [:automatic_return,           '3'],
          [:reference_payment,          '4'],
          [:recurring_transaction,      '5'],
          [:successive_transaction,     '6'],
          [:authentication,             '7'],
          [:confirm_authentication,     '8'],
          [:cancel_preauthorization,    '9'],
          [:deferred_authorization,             'O'],
          [:confirm_deferred_authorization,     'P'],
          [:cancel_deferred_authorization,      'Q'],
          [:inicial_recurring_authorization,    'R'],
          [:successive_recurring_authorization, 'S']
        ]
      end

      def self.response_code_message(code)
        case code.to_i
        when 0..99
          nil
        when 900
          "Transacción autorizada para devoluciones y confirmaciones"
        when 101
          "Tarjeta caducada"
        when 102
          "Tarjeta en excepción transitoria o bajo sospecha de fraude"
        when 104
          "Operación no permitida para esa tarjeta o terminal"
        when 116
          "Disponible insuficiente"
        when 118
          "Tarjeta no registrada o Método de pago no disponible para su tarjeta"
        when 129
          "Código de seguridad (CVV2/CVC2) incorrecto"
        when 180
          "Tarjeta no válida o Tarjeta ajena al servicio o Error en la llamada al MPI sin controlar."
        when 184
          "Error en la autenticación del titular"
        when 190
          "Denegación sin especificar Motivo"
        when 191
          "Fecha de caducidad errónea"
        when 202
          "Tarjeta en excepción transitoria o bajo sospecha de fraude con retirada de tarjeta"
        when 912,9912
          "Emisor no disponible"
        when 913
          "Pedido repetido"
        else
          "Transacción denegada"
        end
      end

      class Return < OffsitePayments::Return
      end

      class Helper < OffsitePayments::Helper
        class << self
          # Credentials should be set as a hash containing the fields:
          #  :terminal_id, :commercial_id, :secret_key, :key_type (optional)
          attr_accessor :credentials
        end

        mapping :account,     'Ds_Merchant_MerchantName'

        mapping :currency,    'Ds_Merchant_Currency'
        mapping :amount,      'Ds_Merchant_Amount'

        mapping :order,       'Ds_Merchant_Order'
        mapping :description, 'Ds_Merchant_ProductDescription'
        mapping :client,      'Ds_Merchant_Titular'

        mapping :notify_url,  'Ds_Merchant_MerchantURL'
        mapping :success_url, 'Ds_Merchant_UrlOK'
        mapping :failure_url, 'Ds_Merchant_UrlKO'

        mapping :language,    'Ds_Merchant_ConsumerLanguage'

        mapping :transaction_type, 'Ds_Merchant_TransactionType'

        mapping :customer_name, 'Ds_Merchant_Titular'

        mapping :sum_total,   'Ds_Merchant_SumTotal'
        mapping :frequency,   'Ds_Merchant_DateFrecuency'
        mapping :expiry_date, 'Ds_Merchant_ChargeExpiryDate'

        #### Special Request Specific Fields ####
        mapping :signature,   'Ds_Merchant_MerchantSignature'
        ########

        # ammount should always be provided in cents!
        def initialize(order, account, options = {})
          self.credentials = options.delete(:credentials) if options[:credentials]
          super(order, account, options)

          add_field 'Ds_Merchant_MerchantCode', credentials[:commercial_id]
          add_field 'Ds_Merchant_Terminal', credentials[:terminal_id]
          add_field mappings[:transaction_type], '0' # Default Transaction Type
          #self.transaction_type = :authorization
        end

        # Allow credentials to be overwritten if needed
        def credentials
          @credentials || self.class.credentials
        end
        def credentials=(creds)
          @credentials = (self.class.credentials || {}).dup.merge(creds)
        end

        def amount=(money)
          cents = money.respond_to?(:cents) ? money.cents : money
          if money.is_a?(String) || cents.to_i <= 0
            raise ArgumentError, 'money amount must be either a Money object or a positive integer in cents.'
          end
          add_field mappings[:amount], cents.to_i
        end

        def order=(order_id)
          order_id = order_id.to_s
          if order_id !~ /^[0-9]{4}/ && order_id.length <= 8
            order_id = ('0' * 4) + order_id
          end
          regexp = /^[0-9]{4}[0-9a-zA-Z]{0,8}$/
          raise "Invalid order number format! First 4 digits must be numbers" if order_id !~ regexp
          add_field mappings[:order], order_id
        end

        def currency=(value)
          add_field mappings[:currency], Redsys.currency_code(value)
        end

        def language(lang)
          add_field mappings[:language], Redsys.language_code(lang)
        end

        def transaction_type(type)
          add_field mappings[:transaction_type], Redsys.transaction_code(type)
        end

        def form_fields
          add_field mappings[:signature], sign_request
          @fields
        end


        # Send a manual request for the currently prepared transaction.
        # This is an alternative to the normal view helper and is useful
        # for special types of transaction.
        def send_transaction
          body = build_xml_request

          headers = { }
          headers['Content-Length'] = body.size.to_s
          headers['User-Agent'] = "Active Merchant -- http://activemerchant.org"
          headers['Content-Type'] = 'application/x-www-form-urlencoded'

          # Return the raw response data
          ssl_post(Redsys.operations_url, "entrada="+CGI.escape(body), headers)
        end

        protected

        def build_xml_request
          xml = Builder::XmlMarkup.new :indent => 2
          xml.DATOSENTRADA do
            xml.DS_Version 0.1
            xml.DS_MERCHANT_CURRENCY @fields['Ds_Merchant_Currency']
            xml.DS_MERCHANT_AMOUNT @fields['Ds_Merchant_Amount']
            xml.DS_MERCHANT_MERCHANTURL @fields['Ds_Merchant_MerchantURL']
            xml.DS_MERCHANT_TRANSACTIONTYPE @fields['Ds_Merchant_TransactionType']
            xml.DS_MERCHANT_MERCHANTDATA @fields['Ds_Merchant_ProductDescription']
            xml.DS_MERCHANT_TERMINAL credentials[:terminal_id]
            xml.DS_MERCHANT_MERCHANTCODE credentials[:commercial_id]
            xml.DS_MERCHANT_ORDER @fields['Ds_Merchant_Order']
            xml.DS_MERCHANT_MERCHANTSIGNATURE sign_request
          end
          xml.target!
        end


        # Generate a signature authenticating the current request.
        # Values included in the signature are determined by the the type of
        # transaction.
        def sign_request
          str = @fields['Ds_Merchant_Amount'].to_s +
            @fields['Ds_Merchant_Order'].to_s +
            @fields['Ds_Merchant_MerchantCode'].to_s +
            @fields['Ds_Merchant_Currency'].to_s

          case Redsys.transaction_from_code(@fields['Ds_Merchant_TransactionType'])
          when :recurring_transaction
            str += @fields['Ds_Merchant_SumTotal']
          end

          if credentials[:key_type].blank? || credentials[:key_type] == 'sha1_extended'
            str += @fields['Ds_Merchant_TransactionType'].to_s +
              @fields['Ds_Merchant_MerchantURL'].to_s # may be blank!
          end

          str += credentials[:secret_key]

          Digest::SHA1.hexdigest(str)
        end

      end

      class Notification < OffsitePayments::Notification
        def complete?
          status == 'Completed'
        end

        def transaction_id
          params['ds_order']
        end

        # When was this payment received by the client.
        def received_at
          if params['ds_date']
            (day, month, year) = params['ds_date'].split('/')
            Time.parse("#{year}-#{month}-#{day} #{params['ds_hour']}")
          else
            Time.now # Not provided!
          end
        end

        # the money amount we received in cents in X.2 format
        def gross
          sprintf("%.2f", gross_cents / 100.0)
        end

        def gross_cents
          params['ds_amount'].to_i
        end

        # Was this a test transaction?
        def test?
          false
        end

        def currency
          Redsys.currency_from_code(params['ds_currency'])
        end

        # Status of transaction. List of possible values:
        # <tt>Completed</tt>
        # <tt>Failed</tt>
        # <tt>Pending</tt>
        def status
          return 'Failed' if error_code
          case response.to_i
          when 0..99
            'Completed'
          when 900
            'Pending'
          else
            'Failed'
          end
        end

        def error_code
          params['ds_errorcode']
        end

        def response
          params['ds_response']
        end

        def error_message
          msg = Redsys.response_code_message(response)
          response.to_s + ' - ' + (msg.nil? ? 'Operación Aceptada' : msg)
        end

        def secure_payment?
          params['ds_securepayment'] == '1'
        end

        # Acknowledge the transaction.
        #
        # Validate the details provided by the gateway by ensuring that the signature
        # matches up with the details provided.
        #
        # Optionally, a set of credentials can be provided that should contain a
        # :secret_key instead of using the global credentials defined in the Redsys::Helper.
        #
        # Example:
        #
        #   def notify
        #     notify = Redsys::Notification.new(request.query_parameters)
        #
        #     if notify.acknowledge
        #       ... process order ... if notify.complete?
        #     else
        #       ... log possible hacking attempt ...
        #     end
        #
        #
        def acknowledge(credentials = nil)
          return false if params['ds_signature'].blank?
          str =
            params['ds_amount'].to_s +
            params['ds_order'].to_s +
            params['ds_merchantcode'].to_s +
            params['ds_currency'].to_s +
            params['ds_response'].to_s
          if xml?
            str += params['ds_transactiontype'].to_s + params['ds_securepayment'].to_s
          end

          str += (credentials || Redsys::Helper.credentials)[:secret_key]
          sig = Digest::SHA1.hexdigest(str)
          sig.upcase == params['ds_signature'].to_s.upcase
        end

        private

        def xml?
          !params['code'].blank?
        end

        # Take the posted data and try to extract the parameters.
        #
        # Posted data can either be a parameters hash, XML string or CGI data string
        # of parameters.
        #
        def parse(post)
          if post.is_a?(Hash)
            @raw = post.inspect.to_s
            post.each { |key, value|  params[key.downcase] = value }
          elsif post.to_s =~ /<retornoxml>/i
            # XML source
            @raw = post.to_s
            self.params = xml_response_to_hash(raw)
          else
            @raw = post.to_s
            for line in raw.split('&')
              key, value = *line.scan( %r{^([A-Za-z0-9_.]+)\=(.*)$} ).flatten
              params[key.downcase] = CGI.unescape(value)
            end
          end
        end

        def xml_response_to_hash(xml)
          result = { }
          doc = Nokogiri::XML(xml)
          result['code'] = doc.css('RETORNOXML CODIGO').inner_text
          if result['code'] == '0'
            doc.css('RETORNOXML OPERACION').children.each do |child|
              result[child.name.downcase] = child.inner_text
            end
          else
            result['ds_errorcode'] = result['code']
            doc.css('RETORNOXML RECIBIDO DATOSENTRADA').children.each do |child|
              result[child.name.downcase] = child.inner_text unless child.name == 'text'
            end
          end
          result
        end
      end

    end
  end
end

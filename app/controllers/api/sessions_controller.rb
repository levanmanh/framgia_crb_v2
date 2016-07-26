class Api::SessionsController < ApplicationController
  include Authenticable

  protect_from_forgery with: :null_session
  skip_before_action :authenticate_user!, only: [:create, :destroy]

  respond_to :json

  def create
    user_password = request.headers[:password]
    user_email = request.headers[:email]
    user = user_email.present? && User.find_by(email: user_email)
    if user.present?
      if user.valid_password? user_password
        sign_in user, store: false
        user.generate_authentication_token!
        user.save
        return render json: user, status: 200
      end
    end
    render json: {errors: I18n.t("api.invalid_email_or_password")}, status: 422
  end

  def destroy
    if current_user.nil?
      sign_out current_user
      current_user.generate_authentication_token!
      current_user.save
      render json: {
        message: t("api.success_sign_out")
      }, status: :ok
    else
      render json: {
        message: t("api.error_sign_out")
    end
end

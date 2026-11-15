import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Shield,
  Lock,
  Mail,
  User as UserIcon,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  Database,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { fetchRegisteredUsers } from '../api/client';
import { User } from '../types/forensics';
import { useQuery } from '@tanstack/react-query';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, signup, isAuthenticated } = useAuth();

  const [activeTab, setActiveTab] = useState<'signin' | 'signup'>('signin');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [showAccountsDrawer, setShowAccountsDrawer] = useState<boolean>(false);

  // Sign In Form State
  const [loginIdent, setLoginIdent] = useState<string>('abhiram');
  const [loginPassword, setLoginPassword] = useState<string>('Password123!');

  // Sign Up Form State
  const [signupFullName, setSignupFullName] = useState<string>('');
  const [signupEmail, setSignupEmail] = useState<string>('');
  const [signupUsername, setSignupUsername] = useState<string>('');
  const [signupRole, setSignupRole] = useState<string>('Lead Forensic Examiner');
  const [signupPassword, setSignupPassword] = useState<string>('');
  const [signupConfirmPassword, setSignupConfirmPassword] = useState<string>('');

  // Fetch registered accounts for quick reference
  const { data: registeredUsers, refetch: refetchUsers } = useQuery<User[]>({
    queryKey: ['registered-users'],
    queryFn: fetchRegisteredUsers,
    enabled: showAccountsDrawer,
  });

  // Redirect if already authenticated
  React.useEffect(() => {
    if (isAuthenticated) {
      const from = (location.state as any)?.from?.pathname || '/';
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, location]);

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!loginIdent.trim() || !loginPassword) {
      setErrorMessage('Please enter both username/email and password.');
      return;
    }

    setIsSubmitting(true);
    try {
      const user = await login({
        username_or_email: loginIdent.trim(),
        password: loginPassword,
      });
      setSuccessMessage(`Welcome back, ${user.full_name || user.username}! Initializing session...`);
      setTimeout(() => {
        navigate('/');
      }, 700);
    } catch (err: any) {
      setErrorMessage(err.message || 'Authentication failed. Please check credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!signupEmail.trim() || !signupUsername.trim() || !signupPassword) {
      setErrorMessage('Please fill in all required fields.');
      return;
    }

    if (signupPassword.length < 6) {
      setErrorMessage('Password must be at least 6 characters long.');
      return;
    }

    if (signupPassword !== signupConfirmPassword) {
      setErrorMessage('Passwords do not match.');
      return;
    }

    setIsSubmitting(true);
    try {
      const user = await signup({
        email: signupEmail.trim(),
        username: signupUsername.trim(),
        password: signupPassword,
        full_name: signupFullName.trim() || 'Forensic Investigator',
        role: signupRole,
      });
      setSuccessMessage(`Account registered successfully for ${user.username}! Logging you in...`);
      setTimeout(() => {
        navigate('/');
      }, 700);
    } catch (err: any) {
      setErrorMessage(err.message || 'Registration failed. Email or username may already exist.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const quickFill = (userType: 'examiner' | 'analyst') => {
    if (userType === 'examiner') {
      setLoginIdent('abhiram');
      setLoginPassword('Password123!');
    } else {
      setLoginIdent('analyst');
      setLoginPassword('Password123!');
    }
    setErrorMessage(null);
  };

  return (
    <div className="min-h-screen bg-[#070D1F] flex flex-col justify-center items-center p-4 sm:p-6 text-slate-100 relative overflow-hidden">
      {/* Background Ambient Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-[400px] h-[400px] bg-indigo-600/10 rounded-full blur-[120px] pointer-events-none" />

      {/* Main Container */}
      <div className="w-full max-w-md relative z-10 space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 shadow-xl shadow-blue-500/25 ring-4 ring-blue-500/20 mb-1">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-black tracking-tight text-white">ForensiX AI</h1>
          <p className="text-xs font-semibold text-blue-400 uppercase tracking-widest">
            Digital Forensics & Evidence Reconstruction
          </p>
        </div>

        {/* Card */}
        <div className="bg-[#0E1736]/90 backdrop-blur-xl border border-[#1E2D5A] rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6">
          {/* Tab Selector */}
          <div className="grid grid-cols-2 p-1 bg-[#14214B] rounded-2xl border border-[#1E2D5A] text-xs font-bold">
            <button
              type="button"
              onClick={() => {
                setActiveTab('signin');
                setErrorMessage(null);
                setSuccessMessage(null);
              }}
              className={`py-2 rounded-xl transition-all ${
                activeTab === 'signin'
                  ? 'bg-blue-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab('signup');
                setErrorMessage(null);
                setSuccessMessage(null);
              }}
              className={`py-2 rounded-xl transition-all ${
                activeTab === 'signup'
                  ? 'bg-blue-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Sign Up
            </button>
          </div>

          {/* Feedback Alerts */}
          {errorMessage && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-2xl text-rose-300 text-xs flex items-center gap-2.5 animate-fadeIn">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="p-3.5 bg-emerald-500/10 border border-emerald-500/30 rounded-2xl text-emerald-300 text-xs flex items-center gap-2.5 animate-fadeIn">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* TAB 1: SIGN IN */}
          {activeTab === 'signin' && (
            <form onSubmit={handleSignIn} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <UserIcon className="w-3.5 h-3.5 text-blue-400" />
                  <span>Username or Email</span>
                </label>
                <input
                  type="text"
                  value={loginIdent}
                  onChange={(e) => setLoginIdent(e.target.value)}
                  placeholder="e.g. abhiram or investigator@forensix.ai"
                  required
                  className="w-full px-4 py-2.5 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all font-medium"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-blue-400" />
                  <span>Password</span>
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder="Enter password"
                    required
                    className="w-full px-4 py-2.5 pr-10 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all font-medium"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Quick Fill Demo Credentials */}
              <div className="pt-1">
                <span className="text-[10px] font-semibold text-slate-400 block mb-1.5">
                  Quick-Fill Test Credentials:
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => quickFill('examiner')}
                    className="flex-1 py-1 px-2 rounded-lg bg-[#182859] hover:bg-[#1E3373] text-[11px] font-semibold text-blue-300 border border-[#243B7F] transition-colors flex items-center justify-center gap-1"
                  >
                    <KeyRound className="w-3 h-3 text-blue-400" />
                    <span>Lead Examiner</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => quickFill('analyst')}
                    className="flex-1 py-1 px-2 rounded-lg bg-[#182859] hover:bg-[#1E3373] text-[11px] font-semibold text-slate-300 border border-[#243B7F] transition-colors flex items-center justify-center gap-1"
                  >
                    <KeyRound className="w-3 h-3 text-slate-400" />
                    <span>DFIR Analyst</span>
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-blue-600/30 flex items-center justify-center gap-2 cursor-pointer mt-2"
              >
                {isSubmitting ? (
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                ) : (
                  <Shield className="w-4 h-4" />
                )}
                <span>{isSubmitting ? 'Authenticating...' : 'Sign In to Investigation Console'}</span>
              </button>
            </form>
          )}

          {/* TAB 2: SIGN UP */}
          {activeTab === 'signup' && (
            <form onSubmit={handleSignUp} className="space-y-3.5">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-300">Full Name</label>
                <input
                  type="text"
                  value={signupFullName}
                  onChange={(e) => setSignupFullName(e.target.value)}
                  placeholder="e.g. A. Abhiram"
                  className="w-full px-4 py-2 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 font-medium"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-300 flex items-center gap-1">
                  <Mail className="w-3 h-3 text-blue-400" />
                  <span>Email (or Temporary Mail)</span>
                </label>
                <input
                  type="email"
                  value={signupEmail}
                  onChange={(e) => setSignupEmail(e.target.value)}
                  placeholder="e.g. investigator@forensix.ai"
                  required
                  className="w-full px-4 py-2 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 font-medium"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-300">Username</label>
                  <input
                    type="text"
                    value={signupUsername}
                    onChange={(e) => setSignupUsername(e.target.value)}
                    placeholder="username"
                    required
                    className="w-full px-3 py-2 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 font-medium"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-300">Role</label>
                  <select
                    value={signupRole}
                    onChange={(e) => setSignupRole(e.target.value)}
                    className="w-full px-3 py-2 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white focus:outline-none focus:ring-2 focus:ring-blue-500 font-medium"
                  >
                    <option value="Lead Forensic Examiner">Lead Examiner</option>
                    <option value="Cybersecurity Analyst">DFIR Analyst</option>
                    <option value="Incident Responder">Incident Responder</option>
                    <option value="Academic Researcher">Researcher</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-300">Password</label>
                  <input
                    type="password"
                    value={signupPassword}
                    onChange={(e) => setSignupPassword(e.target.value)}
                    placeholder="Min 6 chars"
                    required
                    className="w-full px-3 py-2 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 font-medium"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-300">Confirm Password</label>
                  <input
                    type="password"
                    value={signupConfirmPassword}
                    onChange={(e) => setSignupConfirmPassword(e.target.value)}
                    placeholder="Repeat"
                    required
                    className="w-full px-3 py-2 bg-[#14214B] border border-[#21356F] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 font-medium"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-emerald-600/30 flex items-center justify-center gap-2 cursor-pointer mt-2"
              >
                {isSubmitting ? (
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                ) : (
                  <Sparkles className="w-4 h-4" />
                )}
                <span>{isSubmitting ? 'Creating Account...' : 'Register Investigator Account'}</span>
              </button>
            </form>
          )}
        </div>

        {/* Database Registered Accounts Quick Reference */}
        <div className="bg-[#0C1530]/80 border border-[#1B2952] rounded-2xl p-4 text-xs">
          <button
            type="button"
            onClick={() => {
              setShowAccountsDrawer(!showAccountsDrawer);
              if (!showAccountsDrawer) refetchUsers();
            }}
            className="w-full flex items-center justify-between text-slate-300 hover:text-white transition-colors"
          >
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-blue-400" />
              <span className="font-bold">Database Accounts Reference (database.db)</span>
            </div>
            {showAccountsDrawer ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showAccountsDrawer && (
            <div className="mt-3 pt-3 border-t border-[#1B2952] space-y-2 text-[11px] text-slate-400">
              <p>
                Stored in SQLite database (<code className="text-blue-300">database.db</code>). Registered emails and accounts:
              </p>
              <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1">
                {registeredUsers && registeredUsers.length > 0 ? (
                  registeredUsers.map((u) => (
                    <div
                      key={u.id}
                      className="p-2 bg-[#121E45] rounded-xl border border-[#1F3169] flex items-center justify-between"
                    >
                      <div>
                        <div className="font-bold text-white">{u.full_name || u.username}</div>
                        <div className="text-[10px] text-blue-400 font-mono">{u.email}</div>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/20 text-blue-300">
                        {u.role}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="text-slate-500 italic">Loading registered accounts...</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};


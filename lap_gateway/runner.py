"""
LAP Gateway Fail-Dead Runner (v1.0.0)

A CLI tool that reads tool call JSON from stdin, invokes through
the gateway, and exits non-zero on denial/failure.

This is the "fail-dead" pattern: if the gateway denies the action
or any error occurs, the process exits with a non-zero code,
preventing the action from proceeding.

Usage:
    echo '{"action_id": "...", ...}' | lap-gateway-runner
    lap-gateway-runner --input request.json
    lap-gateway-runner --help

Exit Codes:
    0   Success - tool invocation completed successfully
    1   General error (invalid input, network error, etc.)
    2   Evaluation denied - action was not approved
    3   Token minting failed (T3)
    4   Tool invocation denied - token invalid or budget exceeded
    5   Tool invocation failed - tool returned an error

Security Properties:
    - Process exits immediately on any denial
    - No partial execution on failure
    - All errors logged to stderr
    - Only success outputs to stdout
"""

import sys
import json
import argparse
import secrets
import asyncio
from typing import Optional, Dict, Any

# Import gateway components
try:
    from .server import (
        LAPGateway, GatewayStore, MockToolConnector,
        _now_utc, CRYPTO_AVAILABLE
    )
    from .crypto import create_key_pair, load_signing_key
    from .tokens import TokenBudget
except ImportError:
    # Allow running as standalone script
    from lap_gateway.server import (
        LAPGateway, GatewayStore, MockToolConnector,
        _now_utc, CRYPTO_AVAILABLE
    )
    from lap_gateway.crypto import create_key_pair, load_signing_key
    from lap_gateway.tokens import TokenBudget


# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_EVALUATION_DENIED = 2
EXIT_MINT_FAILED = 3
EXIT_INVOCATION_DENIED = 4
EXIT_INVOCATION_FAILED = 5


def error_exit(message: str, code: int) -> None:
    """Print error to stderr and exit with code."""
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(code)


def read_input(input_file: Optional[str]) -> Dict[str, Any]:
    """Read JSON input from file or stdin."""
    try:
        if input_file:
            with open(input_file, 'r') as f:
                return json.load(f)
        else:
            return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        error_exit(f"Invalid JSON input: {e}", EXIT_ERROR)
    except FileNotFoundError:
        error_exit(f"Input file not found: {input_file}", EXIT_ERROR)
    except Exception as e:
        error_exit(f"Failed to read input: {e}", EXIT_ERROR)


async def run_evaluation(
    gateway: LAPGateway,
    evidence: Dict[str, Any],
    agent_id: str,
    session_id: str,
) -> Dict[str, Any]:
    """Run action evaluation through gateway."""
    return await gateway.evaluate_action(evidence, agent_id, session_id)


async def run_mint_t3(
    gateway: LAPGateway,
    action_id: str,
    evidence_hash: str,
    decision_hash: str,
    tool_name: str,
    operation: str,
    params: Dict[str, Any],
    session_id: str,
    agent_id: str,
) -> Dict[str, Any]:
    """Mint T3 token for specific invocation."""
    return await gateway.mint_t3_token(
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        tool_name=tool_name,
        operation=operation,
        params=params,
        session_id=session_id,
        agent_id=agent_id,
    )


async def run_invocation(
    gateway: LAPGateway,
    tool_name: str,
    operation: str,
    params: Dict[str, Any],
    token_compact: str,
    caller_id: str,
    session_id: str,
    nonce: Optional[str],
    counter: Optional[int],
) -> Dict[str, Any]:
    """Run tool invocation through gateway."""
    return await gateway.invoke_tool(
        tool_name=tool_name,
        operation=operation,
        params=params,
        token_compact=token_compact,
        caller_id=caller_id,
        session_id=session_id,
        nonce=nonce,
        counter=counter,
    )


async def main_async(args: argparse.Namespace) -> int:
    """Main async entry point."""
    # Read input
    request = read_input(args.input)
    
    # Validate required fields
    if "action_id" not in request:
        error_exit("Missing required field: action_id", EXIT_ERROR)
    if "description" not in request:
        error_exit("Missing required field: description", EXIT_ERROR)
    if "tool_name" not in request:
        error_exit("Missing required field: tool_name", EXIT_ERROR)
    
    # Extract fields
    action_id = request["action_id"]
    description = request["description"]
    tool_name = request["tool_name"]
    operation = request.get("operation", "execute")
    params = request.get("params", {})
    agent_id = request.get("agent_id", "runner_agent")
    session_id = request.get("session_id", secrets.token_urlsafe(16))
    
    # Evidence for evaluation
    evidence = {
        "action_id": action_id,
        "description": description,
        "timestamp_utc": _now_utc().isoformat(),
        "irreversibility": request.get("irreversibility", {"score": 0.1}),
        "outcome_delta": request.get("outcome_delta", {}),
        "necessity_confidence": request.get("necessity_confidence", 0.8),
        "provenance": request.get("provenance", {}),
        "alternatives": request.get("alternatives", []),
    }
    
    # Initialize gateway
    if args.verbose:
        print(f"Initializing gateway...", file=sys.stderr)
    
    signing_key = load_signing_key(
        env_var="LAP_GATEWAY_SIGNING_KEY",
        file_path=args.key_file,
        generate_if_missing=True,
    )
    
    if signing_key is None:
        error_exit("Failed to load or generate signing key", EXIT_ERROR)
    
    gateway = LAPGateway(
        gateway_id=args.gateway_id,
        signing_key=signing_key,
    )
    
    # Register mock tool for testing
    gateway.register_tool(MockToolConnector(tool_name))
    
    # Step 1: Evaluate action
    if args.verbose:
        print(f"Evaluating action: {action_id}", file=sys.stderr)
    
    eval_result = await run_evaluation(gateway, evidence, agent_id, session_id)
    
    outcome = eval_result.get("outcome")
    tier = eval_result.get("tier")
    
    if args.verbose:
        print(f"Evaluation result: {outcome} ({tier})", file=sys.stderr)
    
    if outcome not in ("approve",):
        if outcome == "require_external_review":
            error_exit(
                f"Action requires external review (tier: {tier})",
                EXIT_EVALUATION_DENIED
            )
        elif outcome == "escrow":
            error_exit(
                f"Action escrowed for delayed execution (tier: {tier})",
                EXIT_EVALUATION_DENIED
            )
        else:
            error_exit(
                f"Action denied: {eval_result.get('reason', 'unknown')}",
                EXIT_EVALUATION_DENIED
            )
    
    # Step 2: Get capability token
    capability_token = eval_result.get("capability_token")
    requires_mint = eval_result.get("requires_mint", False)
    
    if requires_mint:
        # T3: Need to mint token for specific invocation
        if args.verbose:
            print(f"Minting T3 token for invocation...", file=sys.stderr)
        
        mint_result = await run_mint_t3(
            gateway=gateway,
            action_id=action_id,
            evidence_hash=eval_result["evidence_hash"],
            decision_hash=eval_result["decision_hash"],
            tool_name=tool_name,
            operation=operation,
            params=params,
            session_id=session_id,
            agent_id=agent_id,
        )
        
        if not mint_result.get("success"):
            error_exit(
                f"T3 token minting failed: {mint_result.get('error', 'unknown')}",
                EXIT_MINT_FAILED
            )
        
        capability_token = mint_result["capability_token"]
    
    if not capability_token:
        error_exit("No capability token received", EXIT_EVALUATION_DENIED)
    
    # Step 3: Invoke tool
    if args.verbose:
        print(f"Invoking tool: {tool_name}.{operation}", file=sys.stderr)
    
    # Generate nonce for T2/T3
    nonce = secrets.token_urlsafe(16) if tier in ("T2_HIGH_STAKES", "T3_CATASTROPHIC") else None
    counter = 1 if tier == "T3_CATASTROPHIC" else None
    
    invoke_result = await run_invocation(
        gateway=gateway,
        tool_name=tool_name,
        operation=operation,
        params=params,
        token_compact=capability_token,
        caller_id=agent_id,
        session_id=session_id,
        nonce=nonce,
        counter=counter,
    )
    
    # Check result
    if not invoke_result.get("success"):
        error_msg = invoke_result.get("error", "unknown error")
        
        # Determine exit code based on error type
        if "BUDGET" in error_msg or "REVOKED" in error_msg or "TOKEN" in error_msg:
            error_exit(f"Invocation denied: {error_msg}", EXIT_INVOCATION_DENIED)
        else:
            error_exit(f"Invocation failed: {error_msg}", EXIT_INVOCATION_FAILED)
    
    # Success - output result
    output = {
        "success": True,
        "action_id": action_id,
        "tier": tier,
        "tool_name": tool_name,
        "operation": operation,
        "result": invoke_result.get("result"),
        "receipt_id": invoke_result.get("receipt", {}).get("receipt_id"),
    }
    
    print(json.dumps(output, indent=2))
    return EXIT_SUCCESS


def main():
    """Main entry point for lap-gateway-runner CLI."""
    parser = argparse.ArgumentParser(
        description="LAP Gateway Fail-Dead Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
    0   Success - tool invocation completed successfully
    1   General error (invalid input, network error, etc.)
    2   Evaluation denied - action was not approved
    3   Token minting failed (T3)
    4   Tool invocation denied - token invalid or budget exceeded
    5   Tool invocation failed - tool returned an error

Examples:
    # Read from stdin
    echo '{"action_id": "test", "description": "Test action", "tool_name": "mock"}' | lap-gateway-runner
    
    # Read from file
    lap-gateway-runner --input request.json
    
    # With verbose output
    lap-gateway-runner --input request.json --verbose
        """
    )
    
    parser.add_argument(
        "--input", "-i",
        help="Input JSON file (default: stdin)"
    )
    parser.add_argument(
        "--gateway-id",
        default="runner_gateway",
        help="Gateway ID (default: runner_gateway)"
    )
    parser.add_argument(
        "--key-file",
        help="Path to signing key file (default: env or generate)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output to stderr"
    )
    
    args = parser.parse_args()
    
    # Check crypto availability
    if not CRYPTO_AVAILABLE:
        error_exit(
            "Ed25519 cryptography required. Install: pip install cryptography",
            EXIT_ERROR
        )
    
    # Run async main
    try:
        exit_code = asyncio.run(main_async(args))
        sys.exit(exit_code)
    except SystemExit:
        raise
    except Exception as e:
        error_exit(f"Unexpected error: {e}", EXIT_ERROR)


if __name__ == "__main__":
    main()

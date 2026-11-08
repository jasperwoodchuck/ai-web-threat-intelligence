export function ErrorState({ message }: { message: string }) {
  return <div className="alert alert-danger" role="alert"><span className="alert-symbol">!</span><div><strong>Analysis could not be completed</strong><p>{message}</p></div></div>;
}

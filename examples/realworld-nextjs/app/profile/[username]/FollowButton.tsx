"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { followAction, unfollowAction } from "../../actions";

export default function FollowButton({
  username,
  following,
}: {
  username: string;
  following: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <button
      className="btn btn-sm btn-outline-secondary action-btn"
      disabled={pending}
      onClick={() =>
        startTransition(async () => {
          if (following) await unfollowAction(username);
          else await followAction(username);
          router.refresh();
        })
      }
    >
      <i className="ion-plus-round" /> {following ? "Unfollow" : "Follow"} {username}
    </button>
  );
}

import { APP_NAME } from "../config/app.ts";
import { useMemo } from "react";

type Props = {
  title: string
}

export default function PageTitle({title}: Props) {
  const fullTitle = useMemo(() => {
    if (!title) {
      return APP_NAME;
    }

    return title + " · " + APP_NAME;
  }, [title]);

  return (
    <title>{fullTitle}</title>
  );
}
